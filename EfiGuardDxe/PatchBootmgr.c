#include "EfiGuardDxe.h"

#include <Library/BaseMemoryLib.h>

VOID* /*t_ImgArchStartBootApplication_XX*/ gOriginalBootmgfwImgArchStartBootApplication = NULL;
UINT8 gBootmgfwImgArchStartBootApplicationBackup[sizeof(gHookTemplate)] = { 0 };

VOID* /*t_ImgArchStartBootApplication_XX*/ gOriginalBootmgrImgArchStartBootApplication = NULL;
UINT8 gBootmgrImgArchStartBootApplicationBackup[sizeof(gHookTemplate)] = { 0 };


//
// Universal template bytes for a "faux call" inline hook
//
CONST UINT8 gHookTemplate[] =
{
#if defined(MDE_CPU_X64)
	0x48, 0xB8,										// mov rax,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// <addr>
#elif defined(MDE_CPU_IA32)
	0xB8,											// mov eax,
	0x00, 0x00, 0x00, 0x00,							// <addr>
#endif
	0x50,											// push [e|r]ax
	0xC3											// ret
};


// Signature for [bootmgfw|bootmgr]!ImgArch[Efi]StartBootApplication
STATIC CONST UINT8 SigImgArchStartBootApplication[] = {
	0x41, 0xB8, 0x09, 0x00, 0x00, 0xD0				// mov r8d, 0D0000009h
};


//
// Shared function called by [bootmgfw|bootmgr]!ImgArch[Efi]StartBootApplication hooks to patch either winload.efi or bootmgr.efi
//
STATIC
EFI_STATUS
EFIAPI
HookedBootManagerImgArchStartBootApplication(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	IN UINT32 BootOption,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments,
	IN VOID* /*t_ImgArchStartBootApplication_XX*/ OriginalFunction,
	IN CONST UINT8* OriginalFunctionBytes
	)
{
	// Restore the original function bytes that we replaced with our hook
	CopyMem(OriginalFunction, OriginalFunctionBytes, sizeof(gHookTemplate));

	// Clear the screen and paint it, paint it bl... green
	CONST INT32 OriginalAttribute = SetConsoleTextColour(EFI_GREEN, TRUE);

	// Get the PE headers
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, ImageSize);
	INPUT_FILETYPE FileType = Unknown;
	if (NtHeaders == NULL)
	{
		Print(L"\r\nHookedBootmanagerImgArchStartBootApplication: PE image at 0x%p with size 0x%lx is invalid!\r\nPress any key to continue anyway, or press ESC to reboot.\r\n",
			ImageBase, ImageSize);
		if (!WaitForKey())
		{
			gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
		goto CallOriginal;
	}

	// Determine if we're starting winload.efi, bootmgr.efi (when booting a WIM), or something else
	FileType = GetInputFileType(ImageBase, (UINTN)ImageSize);
	if (FileType != WinloadEfi && FileType != BootmgrEfi)
	{
		// Nothing for us to do
		DEBUG((DEBUG_INFO, "HookedBootmanagerImgArchStartBootApplication: booting application of type %S; not winload.efi or bootmgr.efi. No further patches will be applied.\r\n",
			FileTypeToString(FileType)));
		goto CallOriginal;
	}

	// Print info
	Print(L"[ %S!ImgArchStartBootApplication ]\r\n", (OriginalFunctionBytes == gBootmgrImgArchStartBootApplicationBackup ? L"bootmgr" : L"bootmgfw"));
	Print(L"ImageBase: 0x%p\r\n", ImageBase);
	Print(L"ImageSize: %lx\r\n", ImageSize);
	Print(L"File type: %S\r\n", FileTypeToString(FileType));
	Print(L"EntryPoint: 0x%p\r\n", ((UINT8*)ImageBase + HEADER_FIELD(NtHeaders, AddressOfEntryPoint)));
	Print(L"AppEntry:\r\n");
	Print(L"  Signature: %a\r\n", AppEntry->Signature);
	Print(L"  Flags: %lx\r\n", AppEntry->Flags);
	Print(L"  GUID: %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\r\n",
		AppEntry->Guid.Data1, AppEntry->Guid.Data2, AppEntry->Guid.Data3,
		AppEntry->Guid.Data4[0], AppEntry->Guid.Data4[1], AppEntry->Guid.Data4[2], AppEntry->Guid.Data4[3],
		AppEntry->Guid.Data4[4], AppEntry->Guid.Data4[5], AppEntry->Guid.Data4[6], AppEntry->Guid.Data4[7]);
#ifdef EFI_DEBUG
	// Stuff likely no one cares about
	Print(L"  Unknown: %lx %lx %lx %lx\r\n", AppEntry->Unknown[0], AppEntry->Unknown[1], AppEntry->Unknown[2], AppEntry->Unknown[3]);
	Print(L"  BcdData:\r\n");
	Print(L"    Type: %lx\r\n", AppEntry->BcdData.Type);
	Print(L"    DataOffset: %lx\r\n", AppEntry->BcdData.DataOffset);
	Print(L"    DataSize: %lx\r\n", AppEntry->BcdData.DataSize);
	Print(L"    ListOffset: %lx\r\n", AppEntry->BcdData.ListOffset);
	Print(L"    NextEntryOffset: %lx\r\n", AppEntry->BcdData.NextEntryOffset);
	Print(L"    Empty: %lx\r\n", AppEntry->BcdData.Empty);
#endif

	if (FileType == WinloadEfi)
	{
		// Patch winload.efi
		PatchWinload(ImageBase,
					NtHeaders);
	}
	else if (FileType == BootmgrEfi)
	{
		// Call PatchBootManager a second time; this time to patch bootmgr.efi
		PatchBootManager(FileType,
						ImageBase,
						ImageSize);
	}

CallOriginal:
	if (FileType == WinloadEfi || FileType == BootmgrEfi)
	{
		// Clear screen
		gST->ConOut->EnableCursor(gST->ConOut, FALSE);
		SetConsoleTextColour((UINTN)((OriginalAttribute >> 4) & 0x7), TRUE);
	}

	// Call the original function to transfer execution to the boot application entry point; normally winload.efi!OslMain or bootmgr.efi!BmMain.
	// If FileType != WinloadEfi && FileType != BootmgrEfi, no further patches will be applied because this is some other application being started.
	CONST BOOLEAN VistaOrSevenBootManager = BootOption == MAX_UINT32;
	return VistaOrSevenBootManager
		? ((t_ImgArchStartBootApplication_Vista)OriginalFunction)(AppEntry, ImageBase, ImageSize, ReturnArguments)
		: ((t_ImgArchStartBootApplication_Eight)OriginalFunction)(AppEntry, ImageBase, ImageSize, BootOption, ReturnArguments);
}

//
// bootmgfw!ImgArchEfiStartBootApplication hook to patch either winload.efi or bootmgr.efi, Windows Vista/7 version.
// This has to be a separate function from the bootmgr hook because their backup and return addresses will differ
//
STATIC
EFI_STATUS
EFIAPI
HookedBootmgfwImgArchEfiStartBootApplication_Vista(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	)
{
	return HookedBootManagerImgArchStartBootApplication(AppEntry,
														ImageBase,
														ImageSize,
														MAX_UINT32,
														ReturnArguments,
														gOriginalBootmgfwImgArchStartBootApplication,
														gBootmgfwImgArchStartBootApplicationBackup);
}

//
// bootmgfw!ImgArch[Efi]StartBootApplication hook to patch either winload.efi or bootmgr.efi, Windows >= 8 version.
// This has to be a separate function from the bootmgr hook because their backup and return addresses will differ
//
STATIC
EFI_STATUS
EFIAPI
HookedBootmgfwImgArchStartBootApplication_Eight(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	IN UINT32 BootOption,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	)
{
	return HookedBootManagerImgArchStartBootApplication(AppEntry,
														ImageBase,
														ImageSize,
														BootOption,
														ReturnArguments,
														gOriginalBootmgfwImgArchStartBootApplication,
														gBootmgfwImgArchStartBootApplicationBackup);
}

//
// bootmgr!ImgArchEfiStartBootApplication hook to patch winload.efi, Windows Vista/7 version.
// This has to be a separate function from the bootmgfw hook because their backup and return addresses will differ
//
STATIC
EFI_STATUS
EFIAPI
HookedBootmgrImgArchEfiStartBootApplication_Vista(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	)
{
	return HookedBootManagerImgArchStartBootApplication(AppEntry,
														ImageBase,
														ImageSize,
														MAX_UINT32,
														ReturnArguments,
														gOriginalBootmgrImgArchStartBootApplication,
														gBootmgrImgArchStartBootApplicationBackup);
}

//
// bootmgr!ImgArch[Efi]StartBootApplication hook to patch winload.efi, Windows >= 8 version.
// This has to be a separate function from the bootmgfw hook because their backup and return addresses will differ
//
STATIC
EFI_STATUS
EFIAPI
HookedBootmgrImgArchStartBootApplication_Eight(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	IN UINT32 BootOption,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	)
{
	return HookedBootManagerImgArchStartBootApplication(AppEntry,
														ImageBase,
														ImageSize,
														BootOption,
														ReturnArguments,
														gOriginalBootmgrImgArchStartBootApplication,
														gBootmgrImgArchStartBootApplicationBackup);
}

//
// Patches the Windows Boot Manager (either bootmgfw.efi or bootmgr.efi; normally the former unless booting a WIM file)
// 
EFI_STATUS
EFIAPI
PatchBootManager(
	IN INPUT_FILETYPE FileType,
	IN VOID* ImageBase,
	IN UINTN ImageSize
	)
{
	if (gBootmgfwHandle == NULL)
		return EFI_NOT_STARTED;

	ASSERT(FileType == BootmgfwEfi || FileType == BootmgrEfi);

	// Get PE headers
	CONST BOOLEAN PatchingBootmgrEfi = FileType == BootmgrEfi;
	CONST CHAR16* ShortFileName = PatchingBootmgrEfi ? L"bootmgr" : L"bootmgfw";
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, ImageSize);
	EFI_STATUS Status;
	if (NtHeaders == NULL)
	{
		Status = EFI_LOAD_ERROR;
		Print(L"\r\nPatchBootManager: %S.efi PE image at 0x%p with size 0x%llx is invalid!\r\nPress any key to continue anyway, or press ESC to reboot.\r\n",
			ShortFileName, ImageBase, ImageSize);
		if (!WaitForKey())
		{
			gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
		}
		goto Exit;
	}

	// Print file and version info
	UINT16 MajorVersion = 0, MinorVersion = 0, BuildNumber = 0, Revision = 0;
	Status = GetPeFileVersionInfo(ImageBase, &MajorVersion, &MinorVersion, &BuildNumber, &Revision, NULL);
	if (EFI_ERROR(Status))
		Print(L"\r\nPatchBootManager: WARNING: failed to obtain %S.efi version info. Status: %llx\r\n", ShortFileName, Status);
	else
	{
		Print(L"\r\nPatching %S.efi v%u.%u.%u.%u...\r\n", ShortFileName, MajorVersion, MinorVersion, BuildNumber, Revision);

		// Check if this is a supported boot manager version. All patches should work on all versions since Vista SP1,
		// except for the ImgpFilterValidationFailure patch because this function only exists on Windows 7 and higher.
		if (BuildNumber < 6001)
		{
			Print(L"\r\nPatchBootManager: ERROR: Unsupported %S.efi image version.\r\n"
				L"The minimum supported boot manager version is Windows Vista SP1.\r\n"
				L"It is recommended to use the Windows 10 boot manager even when running an older OS.\r\n", ShortFileName);
			Status = EFI_UNSUPPORTED;
			goto Exit;
		}
	}

	// Find [bootmgfw|bootmgr]!ImgArch[Efi]StartBootApplication
	CONST CHAR16* FunctionName = BuildNumber >= 17134 ? L"ImgArchStartBootApplication" : L"ImgArchEfiStartBootApplication";
	CONST PEFI_IMAGE_SECTION_HEADER CodeSection = IMAGE_FIRST_SECTION(NtHeaders);
	UINT8* Found = NULL;
	Status = FindPattern(SigImgArchStartBootApplication,
							0xCC,
							sizeof(SigImgArchStartBootApplication),
							(UINT8*)ImageBase + CodeSection->VirtualAddress,
							CodeSection->SizeOfRawData,
							(VOID**)&Found);
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nPatchBootManager: failed to find %S!%S signature. Status: %llx\r\n", ShortFileName, FunctionName, Status);
		goto Exit;
	}

	// Found signature; backtrack to function start
	// Note: pOriginalAddress is a pointer to a (function) pointer, because the original address depends on the type of boot manager we are patching.
	VOID **pOriginalAddress = PatchingBootmgrEfi ? &gOriginalBootmgrImgArchStartBootApplication : &gOriginalBootmgfwImgArchStartBootApplication;
	*pOriginalAddress = (VOID*)BacktrackToFunctionStart(ImageBase, NtHeaders, Found);
	CONST VOID* OriginalAddress = *pOriginalAddress;
	if (OriginalAddress == NULL)
	{
		Print(L"\r\nPatchBootManager: failed to find %S!%S function start [signature at 0x%p].\r\n", ShortFileName, FunctionName, (VOID*)Found);
		Status = EFI_NOT_FOUND;
		goto Exit;
	}

	// Found
	VOID* HookAddress;
	if (BuildNumber < 9200)
		HookAddress = PatchingBootmgrEfi ? (VOID*)&HookedBootmgrImgArchEfiStartBootApplication_Vista : (VOID*)&HookedBootmgfwImgArchEfiStartBootApplication_Vista;
	else
		HookAddress = PatchingBootmgrEfi ? (VOID*)&HookedBootmgrImgArchStartBootApplication_Eight : (VOID*)&HookedBootmgfwImgArchStartBootApplication_Eight;
	UINT8* BackupAddress = PatchingBootmgrEfi ? gBootmgrImgArchStartBootApplicationBackup : gBootmgfwImgArchStartBootApplicationBackup;
	Print(L"\r\nFound %S!%S at 0x%p.\r\n", ShortFileName, FunctionName, (VOID*)OriginalAddress);
	Print(L"Hooked%S%S at 0x%p.\r\n", (PatchingBootmgrEfi ? L"Bootmgr" : L"Bootmgfw"), FunctionName, HookAddress);

	CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL); // Note: implies cli

	// Backup original function prologue
	CopyMem(BackupAddress, (VOID*)OriginalAddress, sizeof(gHookTemplate));

	// Place faux call (push addr, ret) at the start of the function to transfer execution to our hook
	CopyMem((VOID*)OriginalAddress, gHookTemplate, sizeof(gHookTemplate));
	*(UINTN*)((UINT8*)OriginalAddress + 2) = (UINTN)HookAddress;

	gBS->RestoreTPL(Tpl);

	// Patch ImgpValidateImageHash to allow custom boot loaders. This is completely
	// optional (unless booting a custom winload.efi), and failures are ignored
	PatchImgpValidateImageHash(FileType,
								ImageBase,
								NtHeaders);

	if (BuildNumber >= 7600)
	{
		// Patch ImgpFilterValidationFailure so it doesn't silently
		// rat out every violation to a TPM or SI log. Also optional
		PatchImgpFilterValidationFailure(FileType,
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
		Print(L"Successfully patched %S!%S.\r\n", ShortFileName, FunctionName);
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
