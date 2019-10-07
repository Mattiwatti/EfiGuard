#include <Uefi.h>
#include <Pi/PiDxeCis.h>

#include <Protocol/EfiGuard.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/LoadedImage.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiBootManagerLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>


//
// Define whether the loader should prompt for driver configuration or not.
// If this is 0, the defaults are used and Windows will be booted with no user interaction.
// This can be overridden on the command line with -D CONFIGURE_DRIVER=[0|1]
//
#ifndef CONFIGURE_DRIVER
#define CONFIGURE_DRIVER	0
#endif


//
// Paths to the driver to try
//
#define EFIGUARD_DRIVER_FILENAME		L"EfiGuardDxe.efi"
STATIC CHAR16* mDriverPaths[] = {
	L"\\EFI\\Boot\\" EFIGUARD_DRIVER_FILENAME,
	L"\\EFI\\" EFIGUARD_DRIVER_FILENAME,
	L"\\" EFIGUARD_DRIVER_FILENAME
};


STATIC
BOOLEAN
EFIAPI
WaitForKey(
	)
{
	EFI_INPUT_KEY Key = { 0, 0 };
	UINTN Index = 0;
	gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);
	gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);

	return (BOOLEAN)(Key.ScanCode != SCAN_ESC);
}

#if CONFIGURE_DRIVER

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

		EFI_INPUT_KEY Key = { 0, 0 };
		UINTN Index = 0;
		gBS->WaitForEvent(1, &gST->ConIn->WaitForKey, &Index);
		gST->ConIn->ReadKeyStroke(gST->ConIn, &Key);

		if (Key.UnicodeChar == CHAR_LINEFEED || Key.UnicodeChar == CHAR_CARRIAGE_RETURN)
		{
			SelectedChar = DefaultSelection;
			break;
		}

		for (UINTN i = 0; i < NumAcceptedChars; ++i)
		{
			if (Key.UnicodeChar == AcceptedChars[i])
			{
				SelectedChar = Key.UnicodeChar;
				break;
			}
		}

		if (SelectedChar != CHAR_NULL)
			break;
	}

	Print(L"%c\r\n\r\n", SelectedChar);
	return SelectedChar;
}

#endif


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
			VolumeHandle->Close(FileHandle);
			*DevicePath = FileDevicePath(Handles[i], ImagePath);
			CHAR16 *PathString = ConvertDevicePathToText(*DevicePath, TRUE, TRUE);
			DEBUG((DEBUG_INFO, "[LOADER] Found file at %S.\r\n", PathString));
			if (PathString != NULL)
				FreePool(PathString);
			break;
		}
	}

	FreePool(Handles);

	return Status;
}

//
// Find the optimal available console output mode and set it if it's not already the current mode
//
STATIC
EFI_STATUS
EFIAPI
SetHighestAvailableMode(
	VOID
	)
{
	INT32 MaxModeNum = 0;
	UINTN Cols, Rows, MaxColsXRows = 0;

	for (INT32 ModeNum = 0; ModeNum < gST->ConOut->Mode->MaxMode; ModeNum++)
	{
		CONST EFI_STATUS Status = gST->ConOut->QueryMode(gST->ConOut, ModeNum, &Cols, &Rows);
		if (EFI_ERROR(Status))
			continue;

		// Accept only modes where the total of (Rows * Columns) >= the previous known best
		if ((Cols * Rows) >= MaxColsXRows)
		{
			MaxColsXRows = Cols * Rows;
			MaxModeNum = ModeNum;
		}
	}

	if (gST->ConOut->Mode->Mode == MaxModeNum)
	{
		// We're already at the correct mode
		return EFI_SUCCESS;
	}

	return gST->ConOut->SetMode(gST->ConOut, MaxModeNum);
}

//
// Connects all current system handles recursively.
//
STATIC
EFI_STATUS
EFIAPI
BdsLibConnectAllEfi(
	VOID
	)
{
	UINTN HandleCount;
	EFI_HANDLE *HandleBuffer;
	CONST EFI_STATUS Status = gBS->LocateHandleBuffer(AllHandles,
													NULL,
													NULL,
													&HandleCount,
													&HandleBuffer);
	if (EFI_ERROR(Status))
		return Status;

	for (UINTN Index = 0; Index < HandleCount; ++Index)
	{
		gBS->ConnectController(HandleBuffer[Index],
								NULL,
								NULL,
								TRUE);
	}

	if (HandleBuffer != NULL)
		FreePool(HandleBuffer);

	return EFI_SUCCESS;
}

//
// Connects all drivers to all controllers.
//
STATIC
VOID
EFIAPI
BdsLibConnectAllDriversToAllControllers(
	VOID
	)
{
	EFI_STATUS Status;

	do
	{
		//
		// Connect All EFI 1.10 drivers following EFI 1.10 algorithm
		//
		BdsLibConnectAllEfi();

		//
		// Check to see if it's possible to dispatch an more DXE drivers.
		// The BdsLibConnectAllEfi() may have made new DXE drivers show up.
		// If anything is Dispatched Status == EFI_SUCCESS and we will try
		// the connect again.
		//
		Status = gDS->Dispatch();

	} while (!EFI_ERROR(Status));
}

STATIC
EFI_STATUS
EFIAPI
StartAndConfigureDriver(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE* SystemTable
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
								ImageHandle,
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

		Status = gBS->LocateProtocol(&gEfiGuardDriverProtocolGuid,
									NULL,
									(VOID**)&EfiGuardDriverProtocol);
		if (EFI_ERROR(Status))
		{
			Print(L"[LOADER] LocateProtocol failed: %llx (%r).\r\n", Status, Status);
			goto Exit;
		}
	}
	else
	{
		Print(L"[LOADER] The driver is already loaded.\r\n");
		Status = EFI_ALREADY_STARTED;
		goto Exit;
	}

#if CONFIGURE_DRIVER
	//
	// Interactive driver configuration
	//
	Print(L"\r\nChoose the type of DSE bypass to use, or press ENTER for default:\r\n"
		L"    [1] No DSE bypass\r\n    [2] Boot time DSE bypass\r\n    [3] Runtime SetVariable hook (default)\r\n    ");
	CONST UINT16 AcceptedDseBypasses[] = { L'1', L'2', L'3' };
	CONST UINT16 SelectedDseBypass = PromptInput(AcceptedDseBypasses,
												sizeof(AcceptedDseBypasses) / sizeof(UINT16),
												L'3');

	Print(L"Wait for a keypress to continue after each patch stage? (for debugging)\n"
		L"    [1] Yes\r\n    [2] No (default)\r\n    ");
	CONST UINT16 YesNo[] = { L'1', L'2' };
	CONST UINT16 SelectedWaitForKeyPress = PromptInput(YesNo,
											sizeof(YesNo) / sizeof(UINT16),
											L'2');

	EFIGUARD_CONFIGURATION_DATA ConfigData;
	if (SelectedDseBypass == L'1')
		ConfigData.DseBypassMethod = DSE_DISABLE_NONE;
	else if (SelectedDseBypass == L'2')
		ConfigData.DseBypassMethod = DSE_DISABLE_AT_BOOT;
	else
		ConfigData.DseBypassMethod = DSE_DISABLE_SETVARIABLE_HOOK;
	ConfigData.WaitForKeyPress = (BOOLEAN)(SelectedWaitForKeyPress == L'1');

	//
	// Send the configuration data to the driver
	//
	Status = EfiGuardDriverProtocol->Configure(&ConfigData);

	if (EFI_ERROR(Status))
		Print(L"[LOADER] Driver Configure() returned error %llx (%r).\r\n", Status, Status);
#endif

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
		// Filter out non-Windows boot entries.
		// Apply some heuristics based on the device path, which must end in "bootmgfw.efi" or "bootx64.efi".
		// In the latter case we may get false positives, but for some types of boots (WinPE, Windows To Go,
		// and that VM product from Larry Ellison that still can't emulate NVRAM properly), the name will
		// always be bootx64.efi, so this can't be avoided.
		//
		// For the common case, a simpler way would have been to check if the description is "Windows Boot Manager",
		// but it turns out that we need the full path anyway to LoadImage the file with BootPolicy = TRUE.
		//
		BOOLEAN MaybeWindows = FALSE;
		UINTN FileSize;
		VOID* FileBuffer = EfiBootManagerGetLoadOptionBuffer(BootOptions[Index].FilePath, &FullPath, &FileSize);
		if (FileBuffer != NULL)
			FreePool(FileBuffer);

		// EDK2's EfiBootManagerGetLoadOptionBuffer will sometimes give a NULL "full path"
		// from an originally non-NULL file path. If so, swap it back (and don't free it).
		if (FullPath == NULL)
			FullPath = BootOptions[Index].FilePath;

		// Get the text representation of the device path and check it for our suspects
		CHAR16* ConvertedPath = ConvertDevicePathToText(FullPath, FALSE, FALSE);
		if (ConvertedPath != NULL &&
			(StrStr(ConvertedPath, L"bootmgfw.efi") != NULL || StrStr(ConvertedPath, L"BOOTMGFW.EFI") != NULL ||
			StrStr(ConvertedPath, L"bootx64.efi") != NULL || StrStr(ConvertedPath, L"BOOTX64.EFI") != NULL))
		{
			MaybeWindows = TRUE;
		}

		if (ConvertedPath != NULL)
			FreePool(ConvertedPath);

		if (OnlyBootWindows && !MaybeWindows)
		{
			if (FullPath != BootOptions[Index].FilePath)
				FreePool(FullPath);

			// Not Windows; skip this entry
			continue;
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

		// So again, DO NOT call this abortion:
		//BmSetMemoryTypeInformationVariable((BOOLEAN)((BootOptions[Index].Attributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_BOOT));

		// Ensure the image path is connected end-to-end by Dispatch()ing any required drivers through DXE services
		EfiBootManagerConnectDevicePath(BootOptions[Index].FilePath, NULL);

		// Instead of creating a ramdisk and reading the file into it (¿que?), just pass the path we saved earlier.
		// This is the point where the driver kicks in via its LoadImage hook.
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
			Print(L"LoadImage error %llx (%r)\r\n", Status, Status);
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
		ImageInfo->LoadOptionsSize = BootOptions[Index].OptionalDataSize;
		ImageInfo->LoadOptions = BootOptions[Index].OptionalData;

		// "Clean to NULL because the image is loaded directly from the firmware's boot manager." (EDK2) Good call, I agree
		ImageInfo->ParentHandle = NULL;

		// Enable the Watchdog Timer for 5 minutes before calling the image
		gBS->SetWatchdogTimer(5 * 60, 0x0000, 0x00, NULL);

		// Start the image and set the return code in the boot option status
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
	BdsLibConnectAllDriversToAllControllers();

	//
	// Set the highest available console mode and clear the screen
	//
	SetHighestAvailableMode();
	gST->ConOut->ClearScreen(gST->ConOut);

	//
	// Turn off the watchdog timer
	//
	gBS->SetWatchdogTimer(0, 0, 0, NULL);

	//
	// Enable cursor
	//
	gST->ConOut->EnableCursor(gST->ConOut, TRUE);

	//
	// Locate, load, start and configure the driver
	//
	CONST EFI_STATUS DriverStatus = StartAndConfigureDriver(ImageHandle, SystemTable);
	if (DriverStatus == EFI_ALREADY_STARTED)
		return EFI_SUCCESS;

	if (EFI_ERROR(DriverStatus))
	{
		Print(L"\r\nERROR: driver load failed with status %llx (%r).\r\n"
			L"Press any key to continue, or press ESC to return to the firmware or shell.\r\n",
			DriverStatus, DriverStatus);
		if (!WaitForKey())
		{
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
