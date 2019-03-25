#pragma once

// We can't include all of <Uefi/UefiBaseType.h> because MSVC will give some very angry errors, especially w.r.t. GUID types which come from the retarded guiddef.h.
// Instead define the minimum subset required to include <Protocol/EfiGuard.h>
#define EFIAPI __cdecl

typedef ULONG_PTR UINTN;
typedef UINTN RETURN_STATUS;
typedef RETURN_STATUS EFI_STATUS;
typedef GUID EFI_GUID;
typedef CHAR CHAR8;
typedef WCHAR CHAR16;
typedef struct
{
	UINT16 Year;
	UINT8 Month;
	UINT8 Day;
	UINT8 Hour;
	UINT8 Minute;
	UINT8 Second;
	UINT8 Pad1;
	UINT32 Nanosecond;
	INT16 TimeZone;
	UINT8 Daylight;
	UINT8 Pad2;
} EFI_TIME;

// For EFI variable attributes
#include <Uefi/UefiMultiPhase.h>
