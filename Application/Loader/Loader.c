#include <Uefi.h>
#include <Pi/PiDxeCis.h>

#include <Protocol/EfiGuard.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/LegacyBios.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiBootManagerLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>


//
// Paths to the driver to try
//
#define EFIGUARD_DRIVER_FILENAME		L"EfiGuardDxe.efi"
STATIC CHAR16* mDriverPaths[] = {
	L"\\EFI\\Boot\\" EFIGUARD_DRIVER_FILENAME,
	L"\\EFI\\" EFIGUARD_DRIVER_FILENAME,
	L"\\" EFIGUARD_DRIVER_FILENAME
};

STATIC EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL *mTextInputEx = NULL;

VOID
EFIAPI
BmRepairAllControllers(
	IN UINTN ReconnectRepairCount
	);

VOID
EFIAPI
BmSetMemoryTypeInformationVariable(
	IN BOOLEAN Boot
	);

BOOLEAN
EFIAPI
BmIsAutoCreateBootOption(
	IN EFI_BOOT_MANAGER_LOAD_OPTION *BootOption
	);

STATIC
VOID
ResetTextInput(
	VOID
	)
{
	if (mTextInputEx != NULL)
		mTextInputEx->Reset(mTextInputEx, FALSE);
	else
		gST->ConIn->Reset(gST->ConIn, FALSE);
}

STATIC
UINT16
EFIAPI
WaitForKey(
	VOID
	)
{
	EFI_KEY_DATA KeyData = { 0 };
	UINTN Index = 0;
	if (mTextInputEx != NULL)
	{
		gBS->WaitForEvent(1, &mTextInputEx->WaitForKeyEx, &Index);
		mTextInputEx->ReadKeyStrokeEx(mTextInputEx, &KeyData);
	}
	else
	{
		gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);
		gST->ConIn->ReadKeyStroke(gST->ConIn, &KeyData.Key);
	}
	return KeyData.Key.ScanCode;
}

STATIC
UINT16
EFIAPI
WaitForKeyWithTimeout(
	IN UINTN Milliseconds
	)
{
	ResetTextInput();
	gBS->Stall(Milliseconds * 1000);

	EFI_KEY_DATA KeyData = { 0 };
	if (mTextInputEx != NULL)
		mTextInputEx->ReadKeyStrokeEx(mTextInputEx, &KeyData);
	else
		gST->ConIn->ReadKeyStroke(gST->ConIn, &KeyData.Key);

	ResetTextInput();
	return KeyData.Key.ScanCode;
}

STATIC
UINT16
EFIAPI
PromptInput(
	IN CONST UINT16* AcceptedChars,
	IN UINTN NumAcceptedChars,
	IN UINT16 DefaultSelection
	)
{
	UINT16 SelectedChar;

	while (TRUE)
	{
		SelectedChar = CHAR_NULL;

		EFI_KEY_DATA KeyData = { 0 };
		UINTN Index = 0;
		if (mTextInputEx != NULL)
		{
			gBS->WaitForEvent(1, &mTextInputEx->WaitForKeyEx, &Index);
			mTextInputEx->ReadKeyStrokeEx(mTextInputEx, &KeyData);
		}
		else
		{
			gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);
			gST->ConIn->ReadKeyStroke(gST->ConIn, &KeyData.Key);
		}

		if (KeyData.Key.UnicodeChar == CHAR_LINEFEED || KeyData.Key.UnicodeChar == CHAR_CARRIAGE_RETURN)
		{
			SelectedChar = DefaultSelection;
			break;
		}

		for (UINTN i = 0; i < NumAcceptedChars; ++i)
		{
			if (KeyData.Key.UnicodeChar == AcceptedChars[i])
			{
				SelectedChar = KeyData.Key.UnicodeChar;
				break;
			}
		}

		if (SelectedChar != CHAR_NULL)
			break;
	}

	Print(L"%c\r\n\r\n", SelectedChar);
	return SelectedChar;
}

STATIC
CONST CHAR16*
EFIAPI
StriStr(
	IN CONST CHAR16 *String1,
	IN CONST CHAR16 *String2
	)
{
	if (*String2 == L'\0')
		return String1;

	while (*String1 != L'\0')
	{
		CONST CHAR16* FirstMatch = String1;
		CONST CHAR16* String2Ptr = String2;
		CHAR16 String1Char = CharToUpper(*String1);
		CHAR16 String2Char = CharToUpper(*String2Ptr);

		while (String1Char == String2Char && String1Char != L'\0')
		{
			String1++;
			String2Ptr++;

			String1Char = CharToUpper(*String1);
			String2Char = CharToUpper(*String2Ptr);
		}

		if (String2Char == L'\0')
			return FirstMatch;

		if (String1Char == L'\0')
			return NULL;

		String1 = FirstMatch + 1;
	}
	return NULL;
}

// 
// Try to find a file by browsing each device
// 
STATIC
EFI_STATUS
LocateFile(
	IN CHAR16* ImagePath,
	OUT EFI_DEVICE_PATH** DevicePath
	)
{
	*DevicePath = NULL;

	UINTN NumHandles;
	EFI_HANDLE* Handles;
	EFI_STATUS Status = gBS->LocateHandleBuffer(ByProtocol,
												&gEfiSimpleFileSystemProtocolGuid,
												NULL,
												&NumHandles,
												&Handles);
	if (EFI_ERROR(Status))
		return Status;

	DEBUG((DEBUG_INFO, "[LOADER] Number of UEFI Filesystem Devices: %llu\r\n", NumHandles));

	for (UINTN i = 0; i < NumHandles; i++)
	{
		EFI_FILE_IO_INTERFACE *IoDevice;
		Status = gBS->OpenProtocol(Handles[i],
									&gEfiSimpleFileSystemProtocolGuid,
									(VOID**)&IoDevice,
									gImageHandle,
									NULL,
									EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (Status != EFI_SUCCESS)
			continue;

		EFI_FILE_HANDLE VolumeHandle;
		Status = IoDevice->OpenVolume(IoDevice, &VolumeHandle);
		if (EFI_ERROR(Status))
			continue;

		EFI_FILE_HANDLE FileHandle;
		Status = VolumeHandle->Open(VolumeHandle,
									&FileHandle,
									ImagePath,
									EFI_FILE_MODE_READ,
									EFI_FILE_READ_ONLY);
		if (!EFI_ERROR(Status))
		{
			FileHandle->Close(FileHandle);
			VolumeHandle->Close(VolumeHandle);
			*DevicePath = FileDevicePath(Handles[i], ImagePath);
			CHAR16 *PathString = ConvertDevicePathToText(*DevicePath, TRUE, TRUE);
			DEBUG((DEBUG_INFO, "[LOADER] Found file at %S.\r\n", PathString));
			if (PathString != NULL)
				FreePool(PathString);
			break;
		}
		VolumeHandle->Close(VolumeHandle);
	}

	FreePool((VOID*)Handles);

	return Status;
}

//
// Find the optimal available console output mode and set it if it's not already the current mode
//
STATIC
EFI_STATUS
EFIAPI
SetHighestAvailableTextMode(
	VOID
	)
{
	if (gST->ConOut == NULL)
		return EFI_NOT_READY;

	INT32 MaxModeNum = 0;
	UINTN Cols, Rows, MaxWeightedColsXRows = 0;
	EFI_STATUS Status = EFI_SUCCESS;

	for (INT32 ModeNum = 0; ModeNum < gST->ConOut->Mode->MaxMode; ModeNum++)
	{
		Status = gST->ConOut->QueryMode(gST->ConOut, ModeNum, &Cols, &Rows);
		if (EFI_ERROR(Status))
			continue;

		// Accept only modes where the total of (Rows * Columns) >= the previous known best.
		// Use 16:10 as an arbitrary weighting that lies in between the common 4:3 and 16:9 ratios
		CONST UINTN WeightedColsXRows = (16 * Rows) * (10 * Cols);
		if (WeightedColsXRows >= MaxWeightedColsXRows)
		{
			MaxWeightedColsXRows = WeightedColsXRows;
			MaxModeNum = ModeNum;
		}
	}

	if (gST->ConOut->Mode->Mode != MaxModeNum)
	{
		Status = gST->ConOut->SetMode(gST->ConOut, MaxModeNum);
	}

	// Clear screen and enable cursor
	gST->ConOut->ClearScreen(gST->ConOut);
	gST->ConOut->EnableCursor(gST->ConOut, TRUE);

	return Status;
}

STATIC
EFI_STATUS
EFIAPI
StartEfiGuard(
	IN BOOLEAN InteractiveConfiguration
	)
{
	EFIGUARD_DRIVER_PROTOCOL* EfiGuardDriverProtocol;
	EFI_DEVICE_PATH *DriverDevicePath = NULL;

	// 
	// Check if the driver is loaded 
	// 
	EFI_STATUS Status = gBS->LocateProtocol(&gEfiGuardDriverProtocolGuid,
											NULL,
											(VOID**)&EfiGuardDriverProtocol);
	ASSERT((!EFI_ERROR(Status) || Status == EFI_NOT_FOUND));
	if (Status == EFI_NOT_FOUND)
	{
		Print(L"[LOADER] Locating and loading driver file %S...\r\n", EFIGUARD_DRIVER_FILENAME);
		for (UINT32 i = 0; i < ARRAY_SIZE(mDriverPaths); ++i)
		{
			Status = LocateFile(mDriverPaths[i], &DriverDevicePath);
			if (!EFI_ERROR(Status))
				break;
		}
		if (EFI_ERROR(Status))
		{
			Print(L"[LOADER] Failed to find driver file %S.\r\n", EFIGUARD_DRIVER_FILENAME);
			goto Exit;
		}

		EFI_HANDLE DriverHandle = NULL;
		Status = gBS->LoadImage(FALSE, // Request is not from boot manager
								gImageHandle,
								DriverDevicePath,
								NULL,
								0,
								&DriverHandle);
		if (EFI_ERROR(Status))
		{
			Print(L"[LOADER] LoadImage failed: %llx (%r).\r\n", Status, Status);
			goto Exit;
		}

		Status = gBS->StartImage(DriverHandle, NULL, NULL);
		if (EFI_ERROR(Status))
		{
			Print(L"[LOADER] StartImage failed: %llx (%r).\r\n", Status, Status);
			goto Exit;
		}
	}
	else
	{
		ASSERT_EFI_ERROR(Status);
		Print(L"[LOADER] The driver is already loaded.\r\n");
	}

	Status = gBS->LocateProtocol(&gEfiGuardDriverProtocolGuid,
								NULL,
								(VOID**)&EfiGuardDriverProtocol);
	if (EFI_ERROR(Status))
	{
		Print(L"[LOADER] LocateProtocol failed: %llx (%r).\r\n", Status, Status);
		goto Exit;
	}

	if (InteractiveConfiguration)
	{
		//
		// Interactive driver configuration
		//
		Print(L"\r\nChoose the type of DSE bypass to use, or press ENTER for default:\r\n"
			L"    [1] Runtime SetVariable hook (default)\r\n    [2] Boot time DSE bypass\r\n    [3] No DSE bypass\r\n    ");
		CONST UINT16 AcceptedDseBypasses[] = { L'1', L'2', L'3' };
		CONST UINT16 SelectedDseBypass = PromptInput(AcceptedDseBypasses,
													sizeof(AcceptedDseBypasses) / sizeof(UINT16),
													L'1');

		Print(L"Wait for a keypress to continue after each patch stage?\n"
			L"    [1] No (default)\r\n    [2] Yes (for debugging)\r\n    ");
		CONST UINT16 NoYes[] = { L'1', L'2' };
		CONST UINT16 SelectedWaitForKeyPress = PromptInput(NoYes,
														sizeof(NoYes) / sizeof(UINT16),
														L'1');

		EFIGUARD_CONFIGURATION_DATA ConfigData;
		switch (SelectedDseBypass)
		{
		case L'1':
		default:
			ConfigData.DseBypassMethod = DSE_DISABLE_SETVARIABLE_HOOK;
			break;
		case L'2':
			ConfigData.DseBypassMethod = DSE_DISABLE_AT_BOOT;
			break;
		case L'3':
			ConfigData.DseBypassMethod = DSE_DISABLE_NONE;
			break;
		}
		ConfigData.WaitForKeyPress = (BOOLEAN)(SelectedWaitForKeyPress == L'2');

		//
		// Send the configuration data to the driver
		//
		Status = EfiGuardDriverProtocol->Configure(&ConfigData);

		if (EFI_ERROR(Status))
			Print(L"[LOADER] Driver Configure() returned error %llx (%r).\r\n", Status, Status);
	}

Exit:
	if (DriverDevicePath != NULL)
		FreePool(DriverDevicePath);

	return Status;
}

//
// Attempt to boot each Windows boot option in the BootOptions array.
// This function is a combined and simplified version of BootBootOptions (BdsDxe) and EfiBootManagerBoot (UefiBootManagerLib),
// except for the fact that we are of course not in the BDS phase and also not a driver or the platform boot manager.
// The Windows boot manager doesn't have to know about all this, that would only confuse it
//
STATIC
BOOLEAN
TryBootOptionsInOrder(
	IN EFI_BOOT_MANAGER_LOAD_OPTION *BootOptions,
	IN UINTN BootOptionCount,
	IN UINT16 CurrentBootOptionIndex,
	IN BOOLEAN OnlyBootWindows
	)
{
	//
	// Iterate over the boot options 'in BootOrder order'
	//
	EFI_DEVICE_PATH_PROTOCOL* FullPath;
	for (UINTN Index = 0; Index < BootOptionCount; ++Index)
	{
		//
		// This is us
		//
		if (BootOptions[Index].OptionNumber == CurrentBootOptionIndex)
			continue;

		//
		// No LOAD_OPTION_ACTIVE, no load
		//
		if ((BootOptions[Index].Attributes & LOAD_OPTION_ACTIVE) == 0)
			continue;

		//
		// Ignore LOAD_OPTION_CATEGORY_APP entries
		//
		if ((BootOptions[Index].Attributes & LOAD_OPTION_CATEGORY) != LOAD_OPTION_CATEGORY_BOOT)
			continue;

		//
		// Ignore legacy (BBS) entries, unless non-Windows entries are allowed (second boot attempt)
		//
		const BOOLEAN IsLegacy = DevicePathType(BootOptions[Index].FilePath) == BBS_DEVICE_PATH &&
			DevicePathSubType(BootOptions[Index].FilePath) == BBS_BBS_DP;
		if (OnlyBootWindows && IsLegacy)
			continue;

		//
		// Filter out non-Windows boot entries.
		// Check the description first as "Windows Boot Manager" entries are obviously going to boot Windows.
		// However the inverse is not true, i.e. not all entries that boot Windows will have this description.
		//
		BOOLEAN MaybeWindows = FALSE;
		if (BootOptions[Index].Description != NULL &&
			StrStr(BootOptions[Index].Description, L"Windows Boot Manager") != NULL)
		{
			MaybeWindows = TRUE;
		}

		// We need the full path to LoadImage the file with BootPolicy = TRUE.
		UINTN FileSize;
		VOID* FileBuffer = EfiBootManagerGetLoadOptionBuffer(BootOptions[Index].FilePath, &FullPath, &FileSize);
		if (FileBuffer != NULL)
			FreePool(FileBuffer);

		// EDK2's EfiBootManagerGetLoadOptionBuffer will sometimes give a NULL "full path"
		// from an originally non-NULL file path. If so, swap it back (and don't free it).
		if (FullPath == NULL)
			FullPath = BootOptions[Index].FilePath;

		// Get the text representation of the device path
		CHAR16* ConvertedPath = ConvertDevicePathToText(FullPath, FALSE, FALSE);

		// If this is not a named "Windows Boot Manager" entry, apply some heuristics based on the device path,
		// which must end in "bootmgfw.efi" or "bootx64.efi". In the latter case we may get false positives,
		// but for some types of boots the filename will always be bootx64.efi, so this can't be avoided.
		if (!MaybeWindows &&
			ConvertedPath != NULL &&
			(StriStr(ConvertedPath, L"bootmgfw.efi") != NULL || StriStr(ConvertedPath, L"bootx64.efi") != NULL))
		{
			MaybeWindows = TRUE;
		}

		if (OnlyBootWindows && !MaybeWindows)
		{
			if (FullPath != BootOptions[Index].FilePath)
				FreePool(FullPath);
			if (ConvertedPath != NULL)
				FreePool(ConvertedPath);
			
			// Not Windows; skip this entry
			continue;
		}

		// Print what we're booting
		if (ConvertedPath != NULL)
		{
			Print(L"Booting \"%S\"...\r\n    -> %S = %S\r\n",
				(BootOptions[Index].Description != NULL ? BootOptions[Index].Description : L"<null description>"),
				IsLegacy ? L"Legacy path" : L"Path", ConvertedPath);
			FreePool(ConvertedPath);
		}

		//
		// Boot this image.
		//
		// DO NOT: call EfiBootManagerBoot(BootOption) to 'simplify' this process.
		// The driver will not work in this case due to EfiBootManagerBoot calling BmSetMemoryTypeInformationVariable(),
		// which performs a warm reset of the system if, for example, the category of the current boot option changed
		// from 'app' to 'boot'. Which is precisely what we are doing...
		//
		// Change the BootCurrent variable to the option number for our boot selection
		UINT16 OptionNumber = (UINT16)BootOptions[Index].OptionNumber;
		EFI_STATUS Status = gRT->SetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME,
											&gEfiGlobalVariableGuid,
											EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
											sizeof(UINT16),
											&OptionNumber);
		ASSERT_EFI_ERROR(Status);

		// Signal the EVT_SIGNAL_READY_TO_BOOT event
		EfiSignalEventReadyToBoot();
		REPORT_STATUS_CODE(EFI_PROGRESS_CODE, (EFI_SOFTWARE_DXE_BS_DRIVER | EFI_SW_DXE_BS_PC_READY_TO_BOOT_EVENT));

		// Repair system through DriverHealth protocol
		BmRepairAllControllers(0);

		// Save the memory map in the MemoryTypeInformation variable for resuming from ACPI S4 (hibernate)
		BmSetMemoryTypeInformationVariable((BootOptions[Index].Attributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_BOOT);

		// Handle BBS entries
		if (IsLegacy)
		{
			Print(L"\r\nNOTE: EfiGuard does not support legacy (non-UEFI) Windows installations.\r\n"
				L"The legacy OS will be booted, but EfiGuard will not work.\r\nPress any key to acknowledge...\r\n");
			WaitForKey();

			EFI_LEGACY_BIOS_PROTOCOL *LegacyBios;
			Status = gBS->LocateProtocol(&gEfiLegacyBiosProtocolGuid,
										NULL,
										(VOID**)&LegacyBios);
			ASSERT_EFI_ERROR(Status);

			BootOptions[Index].Status = LegacyBios->LegacyBoot(LegacyBios,
															(BBS_BBS_DEVICE_PATH*)BootOptions[Index].FilePath,
															BootOptions[Index].OptionalDataSize,
															BootOptions[Index].OptionalData);
			return !EFI_ERROR(BootOptions[Index].Status);
		}

		// Ensure the image path is connected end-to-end by Dispatch()ing any required drivers through DXE services
		EfiBootManagerConnectDevicePath(BootOptions[Index].FilePath, NULL);

		// Instead of creating a ramdisk and reading the file into it (¿que?), just pass the path we saved earlier.
		// This is the point where the driver kicks in via its LoadImage hook.
		REPORT_STATUS_CODE(EFI_PROGRESS_CODE, PcdGet32(PcdProgressCodeOsLoaderLoad));
		EFI_HANDLE ImageHandle = NULL;
		Status = gBS->LoadImage(TRUE,
								gImageHandle,
								FullPath,
								NULL,
								0,
								&ImageHandle);

		if (FullPath != BootOptions[Index].FilePath)
			FreePool(FullPath);

		if (EFI_ERROR(Status))
		{
			// Unload if execution could not be deferred to avoid a resource leak
			if (Status == EFI_SECURITY_VIOLATION)
				gBS->UnloadImage(ImageHandle);

			Print(L"LoadImage error %llx (%r)\r\n", Status, Status);
			BootOptions[Index].Status = Status;
			continue;
		}

		// Get loaded image info
		EFI_LOADED_IMAGE_PROTOCOL* ImageInfo;
		Status = gBS->OpenProtocol(ImageHandle,
									&gEfiLoadedImageProtocolGuid,
									(VOID**)&ImageInfo,
									gImageHandle,
									NULL,
									EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		ASSERT_EFI_ERROR(Status);

		// Set image load options from the boot option
		if (!BmIsAutoCreateBootOption(&BootOptions[Index]))
		{
			ImageInfo->LoadOptionsSize = BootOptions[Index].OptionalDataSize;
			ImageInfo->LoadOptions = BootOptions[Index].OptionalData;
		}

		// "Clean to NULL because the image is loaded directly from the firmware's boot manager." (EDK2) Good call, I agree
		ImageInfo->ParentHandle = NULL;

		// Enable the Watchdog Timer for 5 minutes before calling the image
		gBS->SetWatchdogTimer((UINTN)(5 * 60), 0x0000, 0x00, NULL);

		// Start the image and set the return code in the boot option status
		REPORT_STATUS_CODE(EFI_PROGRESS_CODE, PcdGet32(PcdProgressCodeOsLoaderStart));
		Status = gBS->StartImage(ImageHandle,
								&BootOptions[Index].ExitDataSize,
								&BootOptions[Index].ExitData);
		BootOptions[Index].Status = Status;
		if (EFI_ERROR(Status))
		{
			Print(L"StartImage error %llx (%r)\r\n", Status, Status);
			continue;
		}

		//
		// Success. Code below is never executed
		//

		// Clear the watchdog timer after the image returns
		gBS->SetWatchdogTimer(0x0000, 0x0000, 0x0000, NULL);

		// Clear the BootCurrent variable
		gRT->SetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME,
						&gEfiGlobalVariableGuid,
						0,
						0,
						NULL);

		if (BootOptions[Index].Status == EFI_SUCCESS)
			return TRUE;
	}

	// All boot attempts failed, or no suitable entries were found
	return FALSE;
}

EFI_STATUS
EFIAPI
UefiMain(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
	)
{
	//
	// Connect all drivers to all controllers
	//
	EfiBootManagerConnectAll();

	//
	// Set the highest available console mode and clear the screen
	//
	SetHighestAvailableTextMode();

	//
	// Turn off the watchdog timer
	//
	gBS->SetWatchdogTimer(0, 0, 0, NULL);

	//
	// Query the console input handle for the Simple Text Input Ex protocol
	//
	gBS->HandleProtocol(gST->ConsoleInHandle, &gEfiSimpleTextInputExProtocolGuid, (VOID **)&mTextInputEx);

	//
	// Allow user to configure the driver by pressing a hotkey
	//
	Print(L"Press <HOME> to configure EfiGuard...\r\n");
	CONST BOOLEAN InteractiveConfiguration = WaitForKeyWithTimeout(1500) == SCAN_HOME;

	//
	// Locate, load, start and configure the driver
	//
	CONST EFI_STATUS DriverStatus = StartEfiGuard(InteractiveConfiguration);
	if (EFI_ERROR(DriverStatus))
	{
		Print(L"\r\nERROR: driver load failed with status %llx (%r).\r\n"
			L"Press any key to continue, or press ESC to return to the firmware or shell.\r\n",
			DriverStatus, DriverStatus);
		if (WaitForKey() == SCAN_ESC)
		{
			gBS->Exit(gImageHandle, DriverStatus, 0, NULL);
			return DriverStatus;
		}
	}

	//
	// Start the "boot through" procedure to boot Windows.
	//
	// First obtain our own boot option number, since we don't want to boot ourselves again
	UINT16 CurrentBootOptionIndex;
	UINT32 Attributes = EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
	UINTN Size = sizeof(CurrentBootOptionIndex);
	CONST EFI_STATUS Status = gRT->GetVariable(EFI_BOOT_CURRENT_VARIABLE_NAME,
												&gEfiGlobalVariableGuid,
												&Attributes,
												&Size,
												&CurrentBootOptionIndex);
	if (EFI_ERROR(Status))
	{
		CurrentBootOptionIndex = 0xFFFF;
		Print(L"WARNING: failed to query the current boot option index variable.\r\n"
			L"This could lead to the current device being booted recursively.\r\n"
			L"If you booted from a removable device, it is recommended that you remove it now.\r\n"
			L"\r\nPress any key to continue...\r\n");
		WaitForKey();
	}

	// Query all boot options, and try each following the order set in the "BootOrder" variable, except
	// (1) Do not boot ourselves again, and
	// (2) The description or filename must indicate the boot option is some form of Windows.
	UINTN BootOptionCount;
	EFI_BOOT_MANAGER_LOAD_OPTION* BootOptions = EfiBootManagerGetLoadOptions(&BootOptionCount, LoadOptionTypeBoot);
	BOOLEAN BootSuccess = TryBootOptionsInOrder(BootOptions,
												BootOptionCount,
												CurrentBootOptionIndex,
												TRUE);
	if (!BootSuccess)
	{
		// We did not find any Windows boot entry; retry without the "must be Windows" restriction.
		BootSuccess = TryBootOptionsInOrder(BootOptions,
											BootOptionCount,
											CurrentBootOptionIndex,
											FALSE);
	}
	EfiBootManagerFreeLoadOptions(BootOptions, BootOptionCount);

	if (BootSuccess)
		return EFI_SUCCESS;

	// We should never reach this unless something is seriously wrong (no boot device / partition table corrupted / catastrophic boot manager failure...)
	Print(L"Failed to boot anything. This is super bad!\r\n"
		L"Press any key to return to the firmware or shell,\r\nwhich will surely fix this and not make things worse.\r\n");
	WaitForKey();

	gBS->Exit(gImageHandle, EFI_SUCCESS, 0, NULL);

	return EFI_SUCCESS;
}
