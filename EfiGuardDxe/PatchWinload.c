#include "EfiGuardDxe.h"

#include <Guid/Acpi.h>
#include <Library/BaseMemoryLib.h>

t_OslFwpKernelSetupPhase1 gOriginalOslFwpKernelSetupPhase1 = NULL;
UINT8 gOslFwpKernelSetupPhase1Backup[sizeof(gHookTemplate)] = { 0 };


// Signature for winload!OslFwpKernelSetupPhase1+XX, where the value of XX needs to be determined by backtracking.
// Windows 10 only. On older OSes, and on Windows 10 as fallback, OslFwpKernelSetupPhase1 is found via xrefs to EfipGetRsdt
STATIC CONST UINT8 SigOslFwpKernelSetupPhase1[] = {
	0xE8, 0xCC, 0xCC, 0xCC, 0xCC,					// call BlpArchSwitchContext
	0x48, 0x8B, 0x05, 0xCC, 0xCC, 0xCC, 0xCC,		// mov rax, gBS
	0xCC, 0x8B, 0xCC,								// mov rdx, XX
	0x48, 0x8B, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC		// mov rcx, EfiImageHandle
};

STATIC UNICODE_STRING ImgpFilterValidationFailureMessage = RTL_CONSTANT_STRING(L"*** Windows is unable to verify the signature of"); // newline, etc etc...

// Signature for winload!BlStatusPrint. This is only needed if winload.efi does not export it (RS4 and earlier)
// Windows 10 only. I could find a universal signature for this, but I rarely need the debugger output anymore...
STATIC CONST UINT8 SigBlStatusPrint[] = {
	0x48, 0x8B, 0xC4,								// mov rax, rsp
	0x48, 0x89, 0x48, 0x08,							// mov [rax+8], rcx
	0x48, 0x89, 0x50, 0x10,							// mov [rax+10h], rdx
	0x4C, 0x89, 0x40, 0x18,							// mov [rax+18h], r8
	0x4C, 0x89, 0x48, 0x20,							// mov [rax+20h], r9
	0x53,											// push rbx
	0x48, 0x83, 0xEC, 0x40,							// sub rsp, 40h
	0xE8, 0xCC, 0xCC, 0xCC, 0xCC,					// call BlBdDebuggerEnabled
	0x84, 0xC0,										// test al, al
	0x74, 0xCC										// jz XX
};


NTSTATUS
EFIAPI
BlStatusPrintNoop(
	IN CONST CHAR16 *Format,
	...
	)
{
	return 0xC00000BBL; // STATUS_NOT_SUPPORTED
}

t_BlStatusPrint gBlStatusPrint = BlStatusPrintNoop;

//
// Gets a loaded module entry from the boot loader's LoadOrderList
//
STATIC
PKLDR_DATA_TABLE_ENTRY
EFIAPI
GetBootLoadedModule(
	IN LIST_ENTRY* LoadOrderListHead,
	IN CHAR16* ModuleName
	)
{
	if (ModuleName == NULL || LoadOrderListHead == NULL)
		return NULL;

	for (LIST_ENTRY* ListEntry = LoadOrderListHead->ForwardLink; ListEntry != LoadOrderListHead; ListEntry = ListEntry->ForwardLink)
	{
		// This is fairly heavy abuse of CR(), but legal C because (only) the first field of a struct is guaranteed to be at offset 0 (C99 6.7.2.1, point 13)
		CONST PBLDR_DATA_TABLE_ENTRY Entry = (PBLDR_DATA_TABLE_ENTRY)BASE_CR(ListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (Entry != NULL && StrnCmp(Entry->KldrEntry.BaseDllName.Buffer, ModuleName, (Entry->KldrEntry.BaseDllName.Length / sizeof(CHAR16))) == 0)
			return &Entry->KldrEntry;
	}
	return NULL;
}

//
// winload.efi!OslFwpKernelSetupPhase1 hook to patch ntoskrnl.exe
//
EFI_STATUS
EFIAPI
HookedOslFwpKernelSetupPhase1(
	IN PLOADER_PARAMETER_BLOCK LoaderBlock
	)
{
	// Restore the original function bytes that we replaced with our hook
	CopyMem((VOID*)gOriginalOslFwpKernelSetupPhase1, gOslFwpKernelSetupPhase1Backup, sizeof(gOslFwpKernelSetupPhase1Backup));

	UINT8* LoadOrderListHeadAddress = (UINT8*)&LoaderBlock->LoadOrderListHead;
	if (gKernelPatchInfo.LegacyLoaderBlock)
	{
		// We are booting Vista or some other fossil, which means that our LOADER_PARAMETER_BLOCK declaration in no way matches what is
		// actually being passed by the loader. Notably, the first four UINT32 fields are absent, so fix up the list entry pointer.
		LoadOrderListHeadAddress -= FIELD_OFFSET(LOADER_PARAMETER_BLOCK, LoadOrderListHead);
	}

	// Get the kernel entry from the loader block's LoadOrderList
	CONST PKLDR_DATA_TABLE_ENTRY KernelEntry = GetBootLoadedModule((LIST_ENTRY*)LoadOrderListHeadAddress, L"ntoskrnl.exe");
	if (KernelEntry == NULL)
	{
		gKernelPatchInfo.Status = EFI_LOAD_ERROR;
		PRINT_KERNEL_PATCH_MSG(L"[HookedOslFwpKernelSetupPhase1] Failed to find ntoskrnl.exe in LoadOrderList!\r\n");
		goto CallOriginal;
	}

	VOID* KernelBase = KernelEntry->DllBase;
	CONST UINT32 KernelSize = KernelEntry->SizeOfImage;
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = KernelBase != NULL && KernelSize > 0
		? RtlpImageNtHeaderEx(KernelBase, (UINTN)KernelSize)
		: NULL;
	if (KernelBase == NULL || KernelSize == 0)
	{
		gKernelPatchInfo.Status = EFI_NOT_FOUND;
		PRINT_KERNEL_PATCH_MSG(L"[HookedOslFwpKernelSetupPhase1] Kernel image at 0x%p with size 0x%lx is invalid!\r\n", KernelBase, KernelSize);
		goto CallOriginal;
	}

	// Patch the kernel
	gKernelPatchInfo.KernelBase = KernelBase;
	gKernelPatchInfo.Status = PatchNtoskrnl(KernelBase,
											NtHeaders);

CallOriginal:
	// No error handling here (not a lot of options). This is done in the ExitBootServices() callback which reads the patch status

	// Call the original function to transfer execution back to winload!OslFwpKernelSetupPhase1
	return gOriginalOslFwpKernelSetupPhase1(LoaderBlock);
}

//
// Patches ImgpValidateImageHash in bootmgfw.efi, bootmgr.efi, and winload.[efi|exe] to allow loading modified kernels and boot loaders.
// Failures are ignored because this patch is not needed for the bootkit to work
//
EFI_STATUS
EFIAPI
PatchImgpValidateImageHash(
	IN INPUT_FILETYPE FileType,
	IN UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	// This works on pretty much anything really
	ASSERT(FileType == WinloadExe || FileType == BootmgfwEfi || FileType == BootmgrEfi || FileType == WinloadEfi);
	CONST CHAR16* ShortName = FileType == BootmgfwEfi ? L"bootmgfw" : (FileType == BootmgrEfi ? L"bootmgr" : L"winload");

	CONST PEFI_IMAGE_SECTION_HEADER CodeSection = IMAGE_FIRST_SECTION(NtHeaders);

	CONST UINT32 CodeSizeOfRawData = CodeSection->SizeOfRawData;
	CONST UINT8* CodeStartVa = ImageBase + CodeSection->VirtualAddress;

	Print(L"== Disassembling .text to find %S!ImgpValidateImageHash ==\r\n", ShortName);
	UINT8* AndMinusFortyOneAddress = NULL;

	// Initialize Zydis
	ZydisDecoder Decoder;
	ZyanStatus Status = ZydisInit(NtHeaders, &Decoder, NULL);
	if (!ZYAN_SUCCESS(Status))
	{
		Print(L"Failed to initialize disassembler engine.\r\n");
		return EFI_LOAD_ERROR;
	}

	CONST UINTN Length = CodeSizeOfRawData;
	UINTN Offset = 0;
	ZyanU64 InstructionAddress;
	ZydisDecodedInstruction Instruction;

	// Start decode loop
	while ((InstructionAddress = (ZyanU64)(CodeStartVa + Offset),
			Status = ZydisDecoderDecodeBuffer(&Decoder,
											(VOID*)InstructionAddress,
											Length - Offset,
											&Instruction)) != ZYDIS_STATUS_NO_MORE_DATA)
	{
		if (!ZYAN_SUCCESS(Status))
		{
			Offset++;
			continue;
		}

		// Check if this is 'and REG32, 0FFFFFFD7h' (only esi and r8d are used here really)
		if (Instruction.operand_count == 3 &&
			(Instruction.length == 3 || Instruction.length == 4) &&
			Instruction.mnemonic == ZYDIS_MNEMONIC_AND &&
			Instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			Instruction.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
			Instruction.operands[1].imm.is_signed == ZYAN_TRUE &&
			Instruction.operands[1].imm.value.s == (ZyanI64)((ZyanI32)0xFFFFFFD7)) // Sign extend to 64 bits
		{
			AndMinusFortyOneAddress = (UINT8*)InstructionAddress;
			break;
		}

		Offset += Instruction.length;
	}

	// Backtrack to function start
	CONST UINT8* ImgpValidateImageHash = BacktrackToFunctionStart(ImageBase, NtHeaders, AndMinusFortyOneAddress);
	if (ImgpValidateImageHash == NULL)
	{
		Print(L"    Failed to find %S!ImgpValidateImageHash%S.\r\n",
			ShortName, (AndMinusFortyOneAddress == NULL ? L" 'and xxx, 0FFFFFFD7h' instruction" : L""));
		return EFI_NOT_FOUND;
	}

	// Apply the patch
	*((UINT32*)ImgpValidateImageHash) = 0xC3C033; // xor eax, eax, ret

	// Print info
	Print(L"    Patched %S!ImgpValidateImageHash [RVA: 0x%X].\r\n",
		ShortName, (UINT32)(ImgpValidateImageHash - ImageBase));

	return EFI_SUCCESS;
}

//
// Patches ImgpFilterValidationFailure in bootmgfw.efi, bootmgr.efi, and winload.[efi|exe]
// Failures are ignored because this patch is not needed for the bootkit to work
//
EFI_STATUS
EFIAPI
PatchImgpFilterValidationFailure(
	IN INPUT_FILETYPE FileType,
	IN UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	// This works on pretty much anything really
	ASSERT(FileType == WinloadExe || FileType == BootmgfwEfi || FileType == BootmgrEfi || FileType == WinloadEfi);
	CONST CHAR16* ShortName = FileType == BootmgfwEfi ? L"bootmgfw" : (FileType == BootmgrEfi ? L"bootmgr" : L"winload");

	// Find .text and/or .rdata sections
	PEFI_IMAGE_SECTION_HEADER PatternSection = NULL, CodeSection = NULL;
	PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		if (CompareMem(Section->Name, ".text", sizeof(".text") - 1) == 0)
			CodeSection = Section;
		if (((FileType == BootmgfwEfi || FileType == BootmgrEfi) &&
			CompareMem(Section->Name, ".text", sizeof(".text") - 1) == 0) // [bootmgfw|bootmgr].efi (usually) has no .rdata section, and starting at .text is always fine
			||
			((FileType == WinloadExe || FileType == WinloadEfi) &&
			CompareMem(Section->Name, ".rdata", sizeof(".rdata") - 1) == 0)) // For winload.[exe|efi] the string is in .rdata
			PatternSection = Section;
		Section++;
	}

	ASSERT(PatternSection != NULL);
	ASSERT(CodeSection != NULL);

	CONST UINT32 PatternStartRva = PatternSection->VirtualAddress;
	CONST UINT32 PatternSizeOfRawData = PatternSection->SizeOfRawData;
	CONST UINT8* PatternStartVa = ImageBase + PatternStartRva;

	CHAR8 SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME + 1];
	CopyMem(SectionName, PatternSection->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
	SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME] = '\0';
	Print(L"\r\n== Searching for load failure string in %a [RVA: 0x%X - 0x%X] ==\r\n",
		SectionName, PatternStartRva, PatternStartRva + PatternSizeOfRawData);

	// Search for the black screen of death string "Windows is unable to verify the integrity of the file [...]"
	UINT8* IntegrityFailureStringAddress = NULL;
	for (UINT8* Address = (UINT8*)PatternStartVa;
		Address < ImageBase + NtHeaders->OptionalHeader.SizeOfImage - ImgpFilterValidationFailureMessage.MaximumLength;
		++Address)
	{
		if (CompareMem(Address, ImgpFilterValidationFailureMessage.Buffer, ImgpFilterValidationFailureMessage.Length) == 0)
		{
			IntegrityFailureStringAddress = Address;
			Print(L"    Found load failure string at 0x%llx.\r\n", (UINTN)IntegrityFailureStringAddress);
			break;
		}
	}

	if (IntegrityFailureStringAddress == NULL)
	{
		Print(L"    Failed to find load failure string.\r\n");
		return EFI_NOT_FOUND;
	}

	CONST UINT32 CodeStartRva = CodeSection->VirtualAddress;
	CONST UINT32 CodeSizeOfRawData = CodeSection->SizeOfRawData;
	CONST UINT8* CodeStartVa = ImageBase + CodeStartRva;

	ZeroMem(SectionName, sizeof(SectionName));
	CopyMem(SectionName, CodeSection->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
	Print(L"== Disassembling %a to find %S!ImgpFilterValidationFailure ==\r\n", SectionName, ShortName);
	UINT8* LeaIntegrityFailureAddress = NULL;

	// Initialize Zydis
	ZydisDecoder Decoder;
	ZyanStatus Status = ZydisInit(NtHeaders, &Decoder, NULL);
	if (!ZYAN_SUCCESS(Status))
	{
		Print(L"Failed to initialize disassembler engine.\r\n");
		return EFI_LOAD_ERROR;
	}

	CONST UINTN Length = CodeSizeOfRawData;
	UINTN Offset = 0;
	ZyanU64 InstructionAddress;
	ZydisDecodedInstruction Instruction;

	// Start decode loop
	while ((InstructionAddress = (ZyanU64)(CodeStartVa + Offset),
			Status = ZydisDecoderDecodeBuffer(&Decoder,
											(VOID*)InstructionAddress,
											Length - Offset,
											&Instruction)) != ZYDIS_STATUS_NO_MORE_DATA)
	{
		if (!ZYAN_SUCCESS(Status))
		{
			Offset++;
			continue;
		}

		// Check if this is "lea REG, ds:[rip + offset_to_bsod_string]"
		if (Instruction.operand_count == 2 && Instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			Instruction.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			Instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP)
		{
			ZyanU64 OperandAddress = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Instruction, &Instruction.operands[1], InstructionAddress, &OperandAddress)) &&
				OperandAddress == (UINTN)IntegrityFailureStringAddress)
			{
				LeaIntegrityFailureAddress = (UINT8*)InstructionAddress;
				Print(L"    Found load instruction for load failure string at 0x%llx.\r\n", (UINTN)LeaIntegrityFailureAddress);
				break;
			}
		}

		Offset += Instruction.length;
	}

	// Backtrack to function start
	CONST UINT8* ImgpFilterValidationFailure = BacktrackToFunctionStart(ImageBase, NtHeaders, LeaIntegrityFailureAddress);
	if (ImgpFilterValidationFailure == NULL)
	{
		Print(L"    Failed to find %S!ImgpFilterValidationFailure%S.\r\n",
			ShortName, (LeaIntegrityFailureAddress == NULL ? L" load failure string load instruction" : L""));
		return EFI_NOT_FOUND;
	}

	// Apply the patch
	*((UINT32*)ImgpFilterValidationFailure) = 0xC3C033; // xor eax, eax, ret

	// Print info
	Print(L"    Patched %S!ImgpFilterValidationFailure [RVA: 0x%X].\r\n\r\n",
		ShortName, (UINT32)(ImgpFilterValidationFailure - ImageBase));

	return EFI_SUCCESS;
}

//
// Finds OslFwpKernelSetupPhase1 in winload.efi
//
EFI_STATUS
EFIAPI
FindOslFwpKernelSetupPhase1(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN PEFI_IMAGE_SECTION_HEADER CodeSection,
	IN PEFI_IMAGE_SECTION_HEADER PatternSection,
	IN BOOLEAN TryPatternMatch,
	OUT UINT8** OslFwpKernelSetupPhase1Address
	)
{
	*OslFwpKernelSetupPhase1Address = NULL;

	CONST UINT8* CodeStartVa = ImageBase + CodeSection->VirtualAddress;
	CONST UINT32 CodeSizeOfRawData = CodeSection->SizeOfRawData;
	CONST UINT8* PatternStartVa = ImageBase + PatternSection->VirtualAddress;

	if (TryPatternMatch)
	{
		// On Windows 10, try simple pattern matching first since it will most likely work
		UINT8* Found = NULL;
		CONST EFI_STATUS Status = FindPattern(SigOslFwpKernelSetupPhase1,
											0xCC,
											sizeof(SigOslFwpKernelSetupPhase1),
											(VOID*)CodeStartVa,
											CodeSizeOfRawData,
											(VOID**)&Found);
		if (!EFI_ERROR(Status))
		{
			// Found signature; backtrack to function start
			*OslFwpKernelSetupPhase1Address = BacktrackToFunctionStart(ImageBase, NtHeaders, Found);
			if (*OslFwpKernelSetupPhase1Address != NULL)
			{
				Print(L"\r\nFound OslFwpKernelSetupPhase1 at 0x%llX.\r\n", (UINTN)(*OslFwpKernelSetupPhase1Address));
				return EFI_SUCCESS; // Found; early out
			}
		}
	}

	// On older versions, use some convoluted but robust logic to find OslFwpKernelSetupPhase1 by matching xrefs to EfipGetRsdt.
	// This of course implies finding EfipGetRsdt first. After that, find all calls to this function, and for each, calculate
	// the distance from the start of the function to the call. OslFwpKernelSetupPhase1 is reliably (Vista through 10)
	// the function that has the smallest value for this distance, i.e. the call happens very early in the function.
	CHAR8 SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME + 1];
	CopyMem(SectionName, PatternSection->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
	SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME] = '\0';
	Print(L"\r\n== Searching for EfipGetRsdt pattern in %a ==\r\n", SectionName);

	// Search for EFI ACPI 2.0 table GUID: { 8868e871-e4f1-11d3-bc22-0080c73c8881 }
	UINT8* PatternAddress = NULL;
	for (UINT8* Address = (UINT8*)PatternStartVa;
		Address < ImageBase + NtHeaders->OptionalHeader.SizeOfImage - sizeof(gEfiAcpi20TableGuid);
		++Address)
	{
		if (CompareGuid((CONST GUID*)Address, &gEfiAcpi20TableGuid))
		{
			PatternAddress = Address;
			Print(L"    Found EFI ACPI 2.0 GUID at 0x%llX.\r\n", (UINTN)PatternAddress);
			break;
		}
	}

	if (PatternAddress == NULL)
	{
		Print(L"    Failed to find EFI ACPI 2.0 GUID.\r\n");
		return EFI_NOT_FOUND;
	}

	Print(L"\r\n== Disassembling .text to find EfipGetRsdt ==\r\n");
	UINT8* LeaEfiAcpiTableGuidAddress = NULL;

	// Initialize Zydis
	ZydisDecoder Decoder;
	ZyanStatus Status = ZydisInit(NtHeaders, &Decoder, NULL);
	if (!ZYAN_SUCCESS(Status))
	{
		Print(L"Failed to initialize disassembler engine.\r\n");
		return EFI_LOAD_ERROR;
	}

	CONST UINTN Length = CodeSizeOfRawData;
	UINTN Offset = 0;
	ZyanU64 InstructionAddress;
	ZydisDecodedInstruction Instruction;

	// Start decode loop
	while ((InstructionAddress = (ZyanU64)(CodeStartVa + Offset),
			Status = ZydisDecoderDecodeBuffer(&Decoder,
											(VOID*)InstructionAddress,
											Length - Offset,
											&Instruction)) != ZYDIS_STATUS_NO_MORE_DATA)
	{
		if (!ZYAN_SUCCESS(Status))
		{
			Offset++;
			continue;
		}

		// Check if this is "lea rcx, ds:[rip + offset_to_acpi20_guid]"
		if (Instruction.operand_count == 2 && Instruction.mnemonic == ZYDIS_MNEMONIC_LEA &&
			Instruction.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
			Instruction.operands[0].reg.value == ZYDIS_REGISTER_RCX &&
			Instruction.operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY &&
			Instruction.operands[1].mem.base == ZYDIS_REGISTER_RIP)
		{
			ZyanU64 OperandAddress = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Instruction, &Instruction.operands[1], InstructionAddress, &OperandAddress)) &&
				OperandAddress == (UINTN)PatternAddress)
			{
				// Check for false positives (BlFwGetSystemTable)
				CONST UINT8* Check = (UINT8*)(CodeStartVa + Offset - 4); // 4 = length of 'lea rdx, [r11+18h]' which precedes this instruction in EfipGetRsdt
				if (Check[0] == 0x49 && Check[1] == 0x8D && Check[2] == 0x53) // If no match, this is not EfipGetRsdt
				{
					LeaEfiAcpiTableGuidAddress = (UINT8*)InstructionAddress;
					Print(L"    Found load instruction for EFI ACPI 2.0 GUID at 0x%llX.\r\n", (UINTN)LeaEfiAcpiTableGuidAddress);
					break;
				}
			}
		}

		Offset += Instruction.length;
	}

	if (LeaEfiAcpiTableGuidAddress == NULL)
	{
		Print(L"    Failed to find load instruction for EFI ACPI 2.0 GUID.\r\n");
		return EFI_NOT_FOUND;
	}

	CONST UINT8* EfipGetRsdt = BacktrackToFunctionStart(ImageBase, NtHeaders, LeaEfiAcpiTableGuidAddress);
	if (EfipGetRsdt == NULL)
	{
		Print(L"    Failed to find EfipGetRsdt.\r\n");
		return EFI_NOT_FOUND;
	}

	Print(L"    Found EfipGetRsdt at 0x%llX.\r\n", (UINTN)EfipGetRsdt);
	Print(L"\r\n== Disassembling .text to find OslFwpKernelSetupPhase1 ==\r\n");
	UINT8* CallEfipGetRsdtAddress = NULL;

	// Start decode loop
	Offset = 0;
	UINTN ShortestDistanceToCall = MAX_UINTN;
	while ((InstructionAddress = (ZyanU64)(CodeStartVa + Offset),
			Status = ZydisDecoderDecodeBuffer(&Decoder,
											(VOID*)InstructionAddress,
											Length - Offset,
											&Instruction)) != ZYDIS_STATUS_NO_MORE_DATA)
	{
		if (!ZYAN_SUCCESS(Status))
		{
			Offset++;
			continue;
		}

		// Check if this is 'call IMM'
		if (Instruction.operand_count == 4 &&
			Instruction.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && Instruction.operands[0].imm.is_relative == ZYAN_TRUE &&
			Instruction.mnemonic == ZYDIS_MNEMONIC_CALL)
		{
			// Check if this is 'call EfipGetRsdt'
			ZyanU64 OperandAddress = 0;
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Instruction, &Instruction.operands[0], InstructionAddress, &OperandAddress)) &&
				OperandAddress == (UINTN)EfipGetRsdt)
			{
				// Calculate the distance from the start of the function to the instruction. OslFwpKernelSetupPhase1 will always have the shortest distance
				CONST UINTN StartOfFunction = (UINTN)BacktrackToFunctionStart(ImageBase, NtHeaders, (UINT8*)InstructionAddress);
				CONST UINTN Distance = InstructionAddress - StartOfFunction;
				if (Distance < ShortestDistanceToCall)
				{
					CallEfipGetRsdtAddress = (UINT8*)InstructionAddress;
					ShortestDistanceToCall = Distance;
				}
			}
		}

		Offset += Instruction.length;
	}

	if (CallEfipGetRsdtAddress == NULL)
	{
		Print(L"    Failed to find a single 'call EfipGetRsdt' instruction.\r\n");
		return EFI_NOT_FOUND;
	}

	// Found
	*OslFwpKernelSetupPhase1Address = CallEfipGetRsdtAddress - ShortestDistanceToCall;
	Print(L"    Found OslFwpKernelSetupPhase1 at 0x%llX.\r\n\r\n", (UINTN)(*OslFwpKernelSetupPhase1Address));

	return EFI_SUCCESS;
}

//
// Patches winload.efi
// 
EFI_STATUS
EFIAPI
PatchWinload(
	IN VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	)
{
	// Print file and version info
	UINT16 MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;
	EFI_STATUS Status = GetPeFileVersionInfo(ImageBase, &MajorVersion, &MinorVersion, &BuildNumber, &Revision, NULL);
	if (EFI_ERROR(Status))
		Print(L"\r\nPatchWinload: WARNING: failed to obtain winload.efi version info. Status: %llx\r\n", Status);
	else
	{
		Print(L"\r\nPatching winload.efi v%u.%u.%u.%u...\r\n", MajorVersion, MinorVersion, BuildNumber, Revision);

		// Check if this is a supported winload version. All patches should work on all versions since Vista SP1,
		// except for the ImgpFilterValidationFailure patch because this function only exists on Windows 7 and higher.
		if (BuildNumber < 6001)
		{
			Print(L"\r\nPatchWinload: ERROR: Unsupported winload.efi image version.\r\n");
			Status = EFI_UNSUPPORTED;
			goto Exit;
		}

		// Some... adjustments... need to be made later on in the case of pre-Windows 7 loader blocks
		gKernelPatchInfo.LegacyLoaderBlock = BuildNumber < 7600;
	}

	// Find the .text and .rdata sections
	PEFI_IMAGE_SECTION_HEADER CodeSection = NULL, PatternSection = NULL;
	PEFI_IMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	for (UINT16 i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		CHAR8 SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME + 1];
		CopyMem(SectionName, Section->Name, EFI_IMAGE_SIZEOF_SHORT_NAME);
		SectionName[EFI_IMAGE_SIZEOF_SHORT_NAME] = '\0';

		if (AsciiStrCmp(SectionName, ".text") == 0)
			CodeSection = Section;
		else if (AsciiStrCmp(SectionName, ".rdata") == 0)
			PatternSection = Section;

		Section++;
	}

	ASSERT(CodeSection != NULL);
	ASSERT(PatternSection != NULL);

	// (Optional) On Windows 10, find winload!BlStatusPrint
	if (BuildNumber >= 10240)
	{
		gBlStatusPrint = (t_BlStatusPrint)GetProcedureAddress((UINTN)ImageBase, NtHeaders, "BlStatusPrint");
		if (gBlStatusPrint == NULL)
		{
			// Not exported (RS4 and earlier) - try to find by signature
			FindPattern(SigBlStatusPrint,
						0xCC,
						sizeof(SigBlStatusPrint),
						(UINT8*)ImageBase + CodeSection->VirtualAddress,
						CodeSection->SizeOfRawData,
						(VOID**)&gBlStatusPrint);
			if (gBlStatusPrint == NULL)
			{
				gBlStatusPrint = BlStatusPrintNoop;
				Print(L"\r\nWARNING: winload!BlStatusPrint not found. No boot debugger output will be available.\r\n");
			}
		}
	}

	// Find winload!OslFwpKernelSetupPhase1
	Status = FindOslFwpKernelSetupPhase1(ImageBase,
										NtHeaders,
										CodeSection,
										PatternSection,
										(BOOLEAN)(BuildNumber >= 10240),
										(UINT8**)&gOriginalOslFwpKernelSetupPhase1);
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPatchWinload: failed to find OslFwpKernelSetupPhase1. Status: %llx\r\n", Status);
		goto Exit;
	}

	Print(L"HookedOslFwpKernelSetupPhase1 at 0x%p.\r\n", (VOID*)&HookedOslFwpKernelSetupPhase1);

	CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL); // Note: implies cli

	// Backup original function prologue
	CopyMem(gOslFwpKernelSetupPhase1Backup, (VOID*)gOriginalOslFwpKernelSetupPhase1, sizeof(gOslFwpKernelSetupPhase1Backup));

	// Place faux call (push addr, ret) at the start of the function to transfer execution to our hook
	CopyMem((VOID*)gOriginalOslFwpKernelSetupPhase1, gHookTemplate, sizeof(gHookTemplate));
	*(UINTN*)((UINT8*)gOriginalOslFwpKernelSetupPhase1 + 2) = (UINTN)&HookedOslFwpKernelSetupPhase1;

	gBS->RestoreTPL(Tpl);

	// Patch ImgpValidateImageHash to allow custom boot loaders. This is completely
	// optional (unless booting a custom ntoskrnl.exe), and failures are ignored
	PatchImgpValidateImageHash(WinloadEfi,
								ImageBase,
								NtHeaders);

	if (BuildNumber >= 7600)
	{
		// Patch ImgpFilterValidationFailure so it doesn't silently
		// rat out every violation to a TPM or SI log. Also optional
		PatchImgpFilterValidationFailure(WinloadEfi,
										ImageBase,
										NtHeaders);
	}

Exit:
	if (EFI_ERROR(Status))
	{
		// Patch failed. Prompt user to ask what they want to do
		Print(L"\r\nPress any key to continue anyway, or press ESC to reboot.\r\n");
		if (!WaitForKey())
		{
			gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
	}
	else
	{
		Print(L"Successfully patched winload!OslFwpKernelSetupPhase1.\r\n");
		RtlSleep(2000);

		if (gDriverConfig.WaitForKeyPress)
		{
			Print(L"\r\nPress any key to continue.\r\n");
			WaitForKey();
		}
	}

	// Return success, because even if the patch failed, the user chose not to reboot above
	return EFI_SUCCESS;
}
