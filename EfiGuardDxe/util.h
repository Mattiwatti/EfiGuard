#pragma once

#include "EfiGuardDxe.h"

#include <Protocol/LoadedImage.h>

//
// Stalls CPU for N milliseconds
//
EFI_STATUS
EFIAPI
RtlSleep(
	IN UINTN Milliseconds
	);

// 
// Prints info about a loaded image
// 
VOID
EFIAPI
PrintLoadedImageInfo(
	IN EFI_LOADED_IMAGE *ImageInfo
	);

//
// Similar to Print(), but for use during the kernel patching phase.
// Do not call this unless the message is specifically intended for (delayed) display output only.
// Instead use the PRINT_KERNEL_PATCH_MSG() macro so the boot debugger receives messages with no delay.
//
VOID
EFIAPI
AppendKernelPatchMessage(
	IN CONST CHAR16 *Format,
	...
	);

//
// Prints the contents of the kernel patch string buffer to the screen using OutputString() calls.
// This is a separate function because the buffer consists of zero or more null-terminated strings,
// which are printed sequentially to prevent issues with platforms that have small Print() buffer limits
//
VOID
EFIAPI
PrintKernelPatchInfo(
	VOID
	);

//
// Waits for a key to be pressed before continuing execution.
// Returns FALSE if ESC was pressed to abort, TRUE otherwise.
//
BOOLEAN
EFIAPI
WaitForKey(
	VOID
	);

//
// Sets the foreground colour while preserving the background colour and optionally clears the screen.
// Returns the original console mode attribute.
//
INT32
EFIAPI
SetConsoleTextColour(
	IN UINTN TextColour,
	IN BOOLEAN ClearScreen
	);

//
// Finds a byte pattern starting at the specified address
//
EFI_STATUS
EFIAPI
FindPattern(
	IN CONST UINT8* Pattern,
	IN UINT8 Wildcard,
	IN UINT32 PatternLength,
	IN CONST VOID* Base,
	IN UINT32 Size,
	OUT VOID **Found
	);

//
// Finds a byte pattern starting at the specified address (with lots of debug spew)
//
EFI_STATUS
EFIAPI
FindPatternVerbose(
	IN CONST UINT8* Pattern,
	IN UINT8 Wildcard,
	IN UINT32 PatternLength,
	IN CONST VOID* Base,
	IN UINT32 Size,
	OUT VOID **Found
	);

typedef struct ZydisFormatter_ ZydisFormatter;

//
// Initializes a ZydisDecoder instance.
// If ZYDIS_DISABLE_FORMATTER is defined, Formatter must be NULL.
// Otherwise it is a required argument.
//
ZyanStatus
EFIAPI
ZydisInit(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	OUT ZydisDecoder *Decoder,
	OUT ZydisFormatter *Formatter OPTIONAL
	);

//
// Finds the start of a function given an address within it.
// Returns NULL if AddressInFunction is NULL (this simplifies error checking logic in calling functions).
//
UINT8*
EFIAPI
BacktrackToFunctionStart(
	IN CONST UINT8* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST UINT8* AddressInFunction
	);
