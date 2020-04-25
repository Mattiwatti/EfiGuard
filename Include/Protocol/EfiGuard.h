#ifndef __EFIGUARD_GUID_H__
#define __EFIGUARD_GUID_H__

#include <Guid/GlobalVariable.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// EfiGuard Bootkit Protocol GUID
//
#define EFI_EFIGUARD_DRIVER_PROTOCOL_GUID \
	{ \
	0x51e4785b, 0xb1e4, 0x4fda, { 0xaf, 0x5f, 0x94, 0x2e, 0xc0, 0x15, 0xf1, 0x7 } \
	}

//
// Type of Driver Signature Enforcement bypass to use
//
typedef enum _EFIGUARD_DSE_BYPASS_TYPE {
	//
	// Do not disable DSE.
	//
	DSE_DISABLE_NONE = 0,

	//
	// Prevent DSE initialization at boot by patching SepInitializeCodeIntegrity.
	// DSE will remain disabled until system reboot.
	//
	// Note: This can be trivially detected. If this is not a problem for you,
	// this is the most convenient option.
	//
	DSE_DISABLE_AT_BOOT = 1,

	//
	// Hook the EFI SetVariable() runtime service to provide a stealth method for writing
	// to any kernel address. This is therefore not a true DSE bypass but simply a backdoor.
	// The most obvious use however is to set g_CiOptions/g_CiEnabled to 0 to load any driver.
	//
	// This is the default DSE bypass setting.
	//
	DSE_DISABLE_SETVARIABLE_HOOK = 2
} EFIGUARD_DSE_BYPASS_TYPE;


//
// Kernel read/write backdoor struct, used in combination with DSE bypass type DSE_DISABLE_SETVARIABLE_HOOK.
// For scalar values, use one of the Byte through Qword fields, set its size in Size, and set IsMemCopy to FALSE.
// For writes, the field that was used to supply the data will contain the original value on return.
//
// To perform a memcpy, set UserBuffer to a pointer-aligned buffer, Size to the size of the buffer, and IsMemCopy to TRUE.
// There is no SEH in UEFI for buffer probing, so it is the caller's responsibility that the address is valid and correctly aligned.
// No backup of the original buffer will be made because this would require memory allocation at runtime. If you wish to obtain
// the contents of the current data at KernelAddress, call the backdoor twice with the first call having IsReadOperation = TRUE.
//
// If IsReadOperation is TRUE, no writes to kernel memory will be performed. Instead either
// (1) one of the Byte through Qword fields (depending on size) will contain the value at KernelAddress, or
// (2) the memcpy performed will be in the opposite direction, i.e. from KernelAddress to UserBuffer.
//
#define EFIGUARD_BACKDOOR_VARIABLE_NAME						L"roodkcaBdrauGifE" // "EfiGuardBackdoor" // TODO: randomize?
#define EFIGUARD_BACKDOOR_VARIABLE_GUID						&gEfiGlobalVariableGuid
#define EFIGUARD_BACKDOOR_VARIABLE_ATTRIBUTES				(EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)
#define EFIGUARD_BACKDOOR_VARIABLE_DATASIZE					sizeof(EFIGUARD_BACKDOOR_DATA)

#define EFIGUARD_BACKDOOR_COOKIE_VALUE						(0xDEADC0DE)

typedef struct _EFIGUARD_BACKDOOR_DATA {

	UINTN CookieValue; // Currently must be EFIGUARD_BACKDOOR_COOKIE_VALUE
	VOID* KernelAddress;

	union {
		struct {
			UINT64 Byte : 8;
			UINT64 Word : 16;
			UINT64 Dword : 32;
			UINT64 Spare : 8;
		} s;

		UINT64 Qword;
		VOID* UserBuffer;
	} u;

	BOOLEAN IsMemCopy;
	BOOLEAN IsReadOperation;
	UINT32 Size;
} EFIGUARD_BACKDOOR_DATA;


//
// Main driver configuration data. This can be optionally sent to the driver using the Configure() pointer in the protocol.
//
typedef struct _EFIGUARD_CONFIGURATION_DATA {
	//
	// Type of Driver Signature Enforcement bypass to use.
	// Default: DSE_DISABLE_SETVARIABLE_HOOK
	//
	EFIGUARD_DSE_BYPASS_TYPE DseBypassMethod;

	//
	// Whether to wait for a keypress at the end of each patch stage, regardless of success or failure.
	// Recommended for debugging purposes only.
	// Default: FALSE
	//
	BOOLEAN WaitForKeyPress;
} EFIGUARD_CONFIGURATION_DATA;


//
// Sends configuration data to the driver.
//
typedef
EFI_STATUS
(EFIAPI*
EFIGUARD_CONFIGURE)(
	IN EFIGUARD_CONFIGURATION_DATA* ConfigurationData
	);


//
// The EfiGuard bootkit driver protocol.
//
typedef struct _EFIGUARD_DRIVER_PROTOCOL {
	EFIGUARD_CONFIGURE Configure;
} EFIGUARD_DRIVER_PROTOCOL;


extern EFI_GUID gEfiGuardDriverProtocolGuid;

#ifdef __cplusplus
}
#endif

#endif
