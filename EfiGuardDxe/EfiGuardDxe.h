#pragma once

#include <Uefi.h>

#include <Protocol/DriverSupportedEfiVersion.h>
#include <Protocol/EfiGuard.h>
#include <Library/UefiLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Zydis/Zydis.h>
#include "ntdef.h"
#include "pe.h"
#include "arc.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// EfiGuard driver protocol handle
//
extern EFIGUARD_DRIVER_PROTOCOL gEfiGuardDriverProtocol;

//
// Driver configuration data
//
extern EFIGUARD_CONFIGURATION_DATA gDriverConfig;

//
// Bootmgfw.efi handle
//
extern EFI_HANDLE gBootmgfwHandle;

//
// Simple Text Input Ex protocol pointer. May be NULL
//
extern EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL* gTextInputEx;

//
// TRUE if ExitBootServices() has been called
//
extern BOOLEAN gEfiAtRuntime;

//
// TRUE if SetVirtualAddressMap() has been called
//
extern BOOLEAN gEfiGoneVirtual;

//
// Universal template bytes for a faux call inline hook (mov [e|r]ax, <addr>, push [e|r]ax, ret)
//
extern CONST UINT8 gHookTemplate[(sizeof(VOID*) / 4) + sizeof(VOID*) + 2];
extern CONST UINTN gHookTemplateAddressOffset;


//
// [bootmgfw|bootmgr]!ImgArch[Efi]StartBootApplication hook to patch either winload.efi or bootmgr.efi
// This function was named ImgArchEfiStartBootApplication on versions <= 10.0.16299.0, later simply ImgArchStartBootApplication.
//
// Windows Vista/7 prototype
typedef
EFI_STATUS
(EFIAPI*
t_ImgArchStartBootApplication_Vista)(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	);

// Windows 8+ prototype
typedef
EFI_STATUS
(EFIAPI*
t_ImgArchStartBootApplication_Eight)(
	IN PBL_APPLICATION_ENTRY AppEntry,
	IN VOID* ImageBase,
	IN UINT32 ImageSize,
	IN UINT32 BootOption,
	OUT PBL_RETURN_ARGUMENTS ReturnArguments
	);

extern VOID* /*t_ImgArchStartBootApplication_XX*/ gOriginalBootmgfwImgArchStartBootApplication;
extern UINT8 gBootmgfwImgArchStartBootApplicationBackup[sizeof(gHookTemplate)];

// This is only used if bootmgr.efi is invoked during the boot process
extern VOID* /*t_ImgArchStartBootApplication_XX*/ gOriginalBootmgrImgArchStartBootApplication;
extern UINT8 gBootmgrImgArchStartBootApplicationBackup[sizeof(gHookTemplate)];


//
// Patches the Windows Boot Manager: either bootmgfw.efi or bootmgr.efi; normally the former unless booting a WIM file
// 
EFI_STATUS
EFIAPI
PatchBootManager(
	IN INPUT_FILETYPE FileType,
	IN VOID* ImageBase,
	IN UINTN ImageSize
	);


//
// winload!OslFwpKernelSetupPhase1 hook
//
typedef
EFI_STATUS
(EFIAPI*
t_OslFwpKernelSetupPhase1)(
	IN PLOADER_PARAMETER_BLOCK LoaderBlock
	);

extern t_OslFwpKernelSetupPhase1 gOriginalOslFwpKernelSetupPhase1;
extern UINT8 gOslFwpKernelSetupPhase1Backup[sizeof(gHookTemplate)];

EFI_STATUS
EFIAPI
HookedOslFwpKernelSetupPhase1(
	IN PLOADER_PARAMETER_BLOCK LoaderBlock
	);


//
// Patches winload.efi
// 
EFI_STATUS
EFIAPI
PatchWinload(
	IN VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	);

//
// Patches ImgpValidateImageHash in bootmgfw.efi, bootmgr.efi, and winload.[efi|exe]
// This patch is completely optional, unless you want to boot a custom kernel or winload image.
// It is applied if possible, but failures are ignored.
//
EFI_STATUS
EFIAPI
PatchImgpValidateImageHash(
	IN INPUT_FILETYPE FileType,
	IN UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	);

//
// Patches ImgpFilterValidationFailure in bootmgfw.efi, bootmgr.efi, and winload.[efi|exe]
// This patch is completely optional, unless you want to boot a custom kernel or winload image.
// It is applied if possible, but failures are ignored.
//
EFI_STATUS
EFIAPI
PatchImgpFilterValidationFailure(
	IN INPUT_FILETYPE FileType,
	IN UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	);

//
// winload!BlStatusPrint. This is not hooked, but used to print debug output to kd or WinDbg
// from the OslFwpKernelSetupPhase1 hook (in which gST->ConOut is no longer available)
//
typedef
NTSTATUS
(EFIAPI*
t_BlStatusPrint)(
	IN CONST CHAR16 *Format,
	...
	);

extern t_BlStatusPrint gBlStatusPrint;

NTSTATUS
EFIAPI
BlStatusPrintNoop(
	IN CONST CHAR16 *Format,
	...
	);


//
// Patches ntoskrnl.exe
// 
EFI_STATUS
EFIAPI
PatchNtoskrnl(
	IN VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders
	);


//
// The kernel patch result. This is used to hold data generated during
// HookedOslFwpKernelSetupPhase1 and PatchNtoskrnl until we can safely access
// boot services to print the output. This is done during the ExitBootServices() callback.
//
// Status holds the final patch status. If this is not EFI_SUCCESS, the buffer holds an
// error message, and the user will be prompted to reboot or continue.
// If Status is EFI_SUCCESS, the buffer holds concatenated patch information similar to what
// is printed during the patching of bootmgfw.efi/bootmgr.efi/winload.efi.
//
typedef struct _KERNEL_PATCH_INFORMATION
{
	EFI_STATUS Status;
	UINTN BufferSize;			// In bytes, excluding null terminator. This may be 0. The maximum buffer size is simply sizeof(Buffer).
	CHAR16 Buffer[8192];		// 8K ought to be enough for everyone
	UINT32 WinloadBuildNumber;	// Used to determine whether the loader block provided by winload.efi will be for Vista (or older) kernels
	UINT32 KernelBuildNumber;	// Used to determine whether an error message should be shown
	VOID* KernelBase;
} KERNEL_PATCH_INFORMATION;

extern KERNEL_PATCH_INFORMATION gKernelPatchInfo;


//
// Appends a kernel patch status info or error message to the buffer for delayed printing,
// and prints it to a boot debugger immediately if one is connected.
//
#define PRINT_KERNEL_PATCH_MSG(Fmt, ...) \
	do { \
		gBlStatusPrint(Fmt, ##__VA_ARGS__); \
		AppendKernelPatchMessage(Fmt, ##__VA_ARGS__); \
	} while (FALSE)

#ifdef __cplusplus
}
#endif
