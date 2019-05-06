#include "EfiGuardDxe.h"
#include "util.h"

#include <Library/UefiLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>

#ifndef ZYDIS_DISABLE_FORMATTER

#include <Library/PrintLib.h>
#include <Zycore/Format.h>

STATIC ZydisFormatterFunc DefaultInstructionFormatter;

#endif

//
// When debugging, we can choose between poor debugging facilities (VirtualBox) or poor performance and Windows compatibility (QEMU).
// (I guess there is also the closed source thing with the horrible user interface that installs 50 drivers on the host (VMware))
// This is a bandaid to make Print() calls readable ...for a while... when using VirtualBox or a live machine with no debugger
//
EFI_STATUS
EFIAPI
RtlSleep(
	IN UINTN Milliseconds
	)
{
	ASSERT(gBS != NULL);
	ASSERT(gBS->Stall != NULL);

	return gBS->Stall(Milliseconds * 1000);
}

VOID
EFIAPI
PrintLoadedImageInfo(
	IN EFI_LOADED_IMAGE *ImageInfo
	)
{
	CHAR16* PathString = ConvertDevicePathToText(ImageInfo->FilePath, TRUE, TRUE);
	Print(L"\r\n[+] %s\r\n", PathString);
	Print(L"    -> ImageBase = %llx\r\n", ImageInfo->ImageBase);
	Print(L"    -> ImageSize = %llx\r\n", ImageInfo->ImageSize);
	if (PathString != NULL)
		FreePool(PathString);
}

VOID
EFIAPI
AppendKernelPatchMessage(
	IN CONST CHAR16 *Format,
	...
	)
{
	ASSERT(gKernelPatchInfo.BufferSize % sizeof(CHAR16) == 0);
	ASSERT(gKernelPatchInfo.BufferSize < sizeof(gKernelPatchInfo.Buffer));

	VA_LIST VaList;
	VA_START(VaList, Format);
	CONST UINTN NumCharsPrinted = UnicodeVSPrint(gKernelPatchInfo.Buffer + (gKernelPatchInfo.BufferSize / sizeof(CHAR16)),
												sizeof(gKernelPatchInfo.Buffer) - gKernelPatchInfo.BufferSize,
												Format,
												VaList);
	VA_END(VaList);

	ASSERT(gKernelPatchInfo.BufferSize + (NumCharsPrinted * sizeof(CHAR16)) < sizeof(gKernelPatchInfo.Buffer));
	gKernelPatchInfo.BufferSize += (NumCharsPrinted * sizeof(CHAR16));

	// Paranoid null terminator (UnicodeVSPrint should do this)
	*(CHAR16*)(gKernelPatchInfo.Buffer + (gKernelPatchInfo.BufferSize / sizeof(CHAR16))) = CHAR_NULL;

	// Separate the next message using the null terminator. This is because most Print() implementations crap out
	// after ~4 lines (depending on PCDs), so we will print the final buffer using multiple calls to Print()
	gKernelPatchInfo.BufferSize += sizeof(CHAR16);
}

VOID
EFIAPI
PrintKernelPatchInfo(
	)
{
	ASSERT(gST->ConOut != NULL);

	UINTN NumChars = gKernelPatchInfo.BufferSize / sizeof(CHAR16);
	if (NumChars * sizeof(CHAR16) >= sizeof(gKernelPatchInfo.Buffer) - sizeof(CHAR16))
		NumChars = sizeof(gKernelPatchInfo.Buffer) - (2 * sizeof(CHAR16)); // Avoid buffer overrun

	CHAR16* String = gKernelPatchInfo.Buffer;
	String[NumChars] = String[NumChars + 1] = CHAR_NULL; // Ensure we have a double null terminator at the end
	UINTN Length;

	// A double null terminator marks the end. It's just like that lovely Win32 getenv API that makes me want to kill myself every time I see it
	while ((Length = StrLen(String)) != 0)
	{
		gST->ConOut->OutputString(gST->ConOut, String);
		String += Length + 1;
	}
}

BOOLEAN
EFIAPI
WaitForKey(
	)
{
	// Hack: because we call this at TPL_NOTIFY in ExitBootServices, we cannot use WaitForEvent()
	// in that scenario because it requires TPL == TPL_APPLICATION. So check the TPL
	CONST EFI_TPL Tpl = EfiGetCurrentTpl();

	EFI_INPUT_KEY Key = { 0, 0 };
	EFI_STATUS Status = EFI_NOT_READY;

	while (Status == EFI_NOT_READY)
	{
		// Can we call WaitForEvent()?
		UINTN Index = 0;
		if (Tpl == TPL_APPLICATION)
			gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index); // Yep
		else
			RtlSleep(1); // Nope; burn CPU. // TODO: find a way to parallelize this to achieve GeForce FX 5800 temperatures

		// At TPL_APPLICATION, we will always get EFI_SUCCESS (barring hardware failures). At higher TPLs we may also get EFI_NOT_READY
		Status = gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);
	}

	ASSERT_EFI_ERROR(Status);
	return (BOOLEAN)(Key.ScanCode != SCAN_ESC);
}

INT32
EFIAPI
SetConsoleTextColour(
	IN UINTN TextColour,
	IN BOOLEAN ClearScreen
	)
{
	CONST INT32 OriginalAttribute = gST->ConOut->Mode->Attribute;
	CONST UINTN BackgroundColour = (UINTN)((OriginalAttribute >> 4) & 0x7);

	gST->ConOut->SetAttribute(gST->ConOut, (TextColour | BackgroundColour));
	if (ClearScreen)
		gST->ConOut->ClearScreen(gST->ConOut);

	return OriginalAttribute;
}

// TODO: #ifdef EFI_DEBUG, this should keep a match count and continue until the end of the buffer, then ASSERT(MatchCount == 1)
EFI_STATUS
EFIAPI
FindPattern(
	IN CONST UINT8* Pattern,
	IN UINT8 Wildcard,
	IN UINT32 PatternLength,
	IN CONST VOID* Base,
	IN UINT32 Size,
	OUT VOID **Found
	)
{
	if (Found == NULL || Pattern == NULL || Base == NULL)
		return EFI_INVALID_PARAMETER;

	*Found = NULL;

	for (UINT8 *Address = (UINT8*)Base; Address < (UINT8*)((UINTN)Base + Size - PatternLength); ++Address)
	{
		UINT32 i;
		for (i = 0; i < PatternLength; ++i)
		{
			if (Pattern[i] != Wildcard && (*(Address + i) != Pattern[i]))
				break;
		}

		if (i == PatternLength)
		{
			*Found = (VOID*)Address;
			return EFI_SUCCESS;
		}
	}

	return EFI_NOT_FOUND;
}

// For debugging non-working signatures. Not that I would ever need to do such a thing of course. Ha ha... ha
// TODO: #ifdef EFI_DEBUG, this should keep a match count and continue until the end of the buffer, then ASSERT(MatchCount == 1)
EFI_STATUS
EFIAPI
FindPatternVerbose(
	IN CONST UINT8* Pattern,
	IN UINT8 Wildcard,
	IN UINT32 PatternLength,
	IN CONST VOID* Base,
	IN UINT32 Size,
	OUT VOID **Found
	)
{
	if (Found == NULL || Pattern == NULL || Base == NULL)
		return EFI_INVALID_PARAMETER;

	*Found = NULL;

	CONST UINTN Start = (UINTN)Base;
	CONST UINTN End = Start + Size - PatternLength;
	EFI_STATUS Status = EFI_NOT_FOUND;

	UINT32 Max = 0;
	UINT8 *AddrOfMax = NULL;

	for (UINT8 *Address = (UINT8*)Start; Address < (UINT8*)End; ++Address)
	{
		UINT32 i;
		for (i = 0; i < PatternLength; ++i)
		{
			if (Pattern[i] != Wildcard  && (*(Address + i) != Pattern[i]))
				break;
		}

		if (i > Max)
		{
			Max = i;
			AddrOfMax = Address;
		}

		if (i == PatternLength)
		{
			*Found = (VOID*)Address;
			Status = EFI_SUCCESS;
		}
	}

	Print(L"\r\nBest match: %lu/%lu matched at 0x%p\r\n", Max, PatternLength, (VOID*)AddrOfMax);

	for (UINT32 i = 0; i < PatternLength && AddrOfMax != NULL; ++i)
	{
		if (Pattern[i] != Wildcard && (*(AddrOfMax + i) != Pattern[i]))
			Print(L"[%lu] [X] %02X != %02X\r\n", i, (*(AddrOfMax + i)), Pattern[i]); // Mismatch
		else if (Pattern[i] == Wildcard)
			Print(L"[%lu] [ ] %02X\r\n", i, (*(AddrOfMax + i))); // Matched wildcard byte
		else
			Print(L"[%lu] [v] %02X\r\n", i, Pattern[i]); // Matched exact byte
	}

	return Status;
}

#ifndef ZYDIS_DISABLE_FORMATTER

// Formatter hook to prefix the opcode bytes to the output
STATIC
ZyanStatus
ZydisInstructionBytesFormatter(
	IN CONST ZydisFormatter* Formatter,
	IN OUT ZydisFormatterBuffer* Buffer,
	IN ZydisFormatterContext* Context
	)
{
	CONST ZyanU8 MaxOpcodeBytes = 12; // Print at most 10 bytes (so 20 characters), with room for ellip.. ses

	ZyanString *String;
	ZYAN_CHECK(ZydisFormatterBufferGetString(Buffer, &String));

	// We cannot use ZyanStringAppendFormat() because at the moment it may use dynamic memory allocation
	// to resize the string buffer, with no way to disable this behaviour. Therefore call AsciiSPrint
	for (ZyanU8 i = 0; i < MaxOpcodeBytes; ++i)
	{
		CONST ZyanUSize Length = String->vector.size;
		UINTN N;

		if (i < Context->instruction->length && i < MaxOpcodeBytes - 2)
		{
			// Print one byte of the instruction
			N = AsciiSPrint((CHAR8*)(String->vector.data) + Length - 1,
							String->vector.capacity - Length + 1,
							"%02X",
							*(UINT8*)(Context->runtime_address + i));
		}
		else if (i < Context->instruction->length && i == MaxOpcodeBytes - 2)
		{
			// This is a huge instruction; truncate remaining bytes with ellipses
			N = AsciiSPrint((CHAR8*)(String->vector.data) + Length - 1,
							String->vector.capacity - Length + 1,
							"%a",
							"..  ");
		}
		else
		{
			// Print an empty string for alignment padding
			N = AsciiSPrint((CHAR8*)(String->vector.data) + Length - 1,
							String->vector.capacity - Length + 1,
							"%a",
							"  ");
		}

		// Do bounds check. According to docs, an ASSERT() should have already happened
		// if we went OOB, but debug asserts may be disabled on this platform
		if ((INTN)N < 0 || N > (UINTN)(String->vector.capacity - Length))
			return ZYAN_STATUS_FAILED;

		String->vector.size += (ZyanUSize)N;
	}

	// Call the default formatter to print the actual instruction text
	return DefaultInstructionFormatter(Formatter, Buffer, Context);
}

#endif

ZyanStatus
EFIAPI
ZydisInit(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT ZydisDecoder *Decoder,
	OUT ZydisFormatter *Formatter OPTIONAL
	)
{
	ZyanStatus Status;
	if (!ZYAN_SUCCESS((Status = ZydisDecoderInit(Decoder,
										IMAGE64(NtHeaders) ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
										IMAGE64(NtHeaders) ? ZYDIS_ADDRESS_WIDTH_64 : ZYDIS_ADDRESS_WIDTH_32))))
		return Status;

#ifdef ZYDIS_DISABLE_FORMATTER
	ASSERT(Formatter == NULL);
#else
	if (!ZYAN_SUCCESS((Status = ZydisFormatterInit(Formatter, ZYDIS_FORMATTER_STYLE_INTEL))))
		return Status;
	if (!ZYAN_SUCCESS((Status = ZydisFormatterSetProperty(Formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE))))
		return Status;

	DefaultInstructionFormatter = (ZydisFormatterFunc)&ZydisInstructionBytesFormatter;
	if (!ZYAN_SUCCESS((Status = ZydisFormatterSetHook(Formatter,
													ZYDIS_FORMATTER_FUNC_FORMAT_INSTRUCTION,
													(CONST VOID**)&DefaultInstructionFormatter))))
		return Status;
#endif

	return ZYAN_STATUS_SUCCESS;
}

UINT8*
EFIAPI
BacktrackToFunctionStart(
	IN CONST UINT8* StartAddress,
	IN CONST UINT8* LowerBound
	)
{
	// Test for null. This allows callers to do 'FindPattern(..., &Address); X = Backtrack(Address, ...)' with a single failure branch
	if (StartAddress == NULL)
		return NULL;

	ASSERT(StartAddress > LowerBound);

	UINT8 *Address;
	BOOLEAN Found = FALSE;
	for (Address = (UINT8*)StartAddress; Address >= LowerBound; --Address)
	{
		if ((*(Address - 1) == 0xCC ||										// Previous byte is int 3 padding, or
			(*(Address - 2) == 0x90 && *(Address - 1) == 0x90) ||			// Previous 2 bytes are nop padding, or
			(*(Address - 4) == 0x00 && *(Address - 3) == 0x00 &&			// Previous 4+ bytes are 00 padding (rare, only happens at start of a section), or
				*(Address - 2) == 0x00 && *(Address - 1) == 0x00) ||
			(*(Address - 1) == 0xC3 && *(Address - 3) != 0x8D)				// Previous byte is 'ret', or
#if defined(MDE_CPU_IA32) || defined(_M_IX86)
			|| (*(Address - 3) == 0xC2 && *(Address - 1) == 0x00)			// Previous 3 bytes are 'ret XX' (x86)
#endif
			)
			&&																// *and*
			(*Address == 0x40 || *Address == 0x55 ||						// Current byte is either 'push [ebp|ebx|rbp|rbx]', 'mov REG, XX' or 'sub REG, XX'
			(Address < StartAddress && *Address == 0x44 && *(Address + 1) == 0x89) ||
			(Address < StartAddress && *Address == 0x48 && *(Address + 1) == 0x83) ||
			(Address < StartAddress && *Address == 0x48 && *(Address + 1) == 0x89) ||
			(Address < StartAddress && *Address == 0x48 && *(Address + 1) == 0x8B) ||
			(Address < StartAddress && *Address == 0x49 && *(Address + 1) == 0x89) ||
			(Address < StartAddress && *Address == 0x4C && *(Address + 1) == 0x8B)))
		{
			Found = TRUE;
			break;
		}
	}

	return Found ? Address : NULL;
}
