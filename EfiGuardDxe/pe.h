#pragma once

#include <IndustryStandard/PeImage.h>


//
// Typedefs
//
typedef EFI_IMAGE_NT_HEADERS32 *PEFI_IMAGE_NT_HEADERS32;
typedef EFI_IMAGE_NT_HEADERS64 *PEFI_IMAGE_NT_HEADERS64;

#if defined(MDE_CPU_X64)
typedef EFI_IMAGE_NT_HEADERS64 EFI_IMAGE_NT_HEADERS, *PEFI_IMAGE_NT_HEADERS;
#elif defined(MDE_CPU_IA32)
typedef EFI_IMAGE_NT_HEADERS32 EFI_IMAGE_NT_HEADERS, *PEFI_IMAGE_NT_HEADERS;
#endif

typedef EFI_IMAGE_DOS_HEADER *PEFI_IMAGE_DOS_HEADER;
typedef EFI_IMAGE_FILE_HEADER *PEFI_IMAGE_FILE_HEADER;
typedef EFI_IMAGE_SECTION_HEADER *PEFI_IMAGE_SECTION_HEADER;
typedef EFI_IMAGE_DATA_DIRECTORY *PEFI_IMAGE_DATA_DIRECTORY;
typedef EFI_IMAGE_EXPORT_DIRECTORY *PEFI_IMAGE_EXPORT_DIRECTORY;

// ACHTUNG: DO NOT USE - EDK2 people didn't read the PE docs re: these it seems. Not very surprising since EFI files don't tend to use imports
//typedef EFI_IMAGE_IMPORT_BY_NAME *PEFI_IMAGE_IMPORT_BY_NAME;
//typedef EFI_IMAGE_THUNK_DATA *PEFI_IMAGE_THUNK_DATA;
//typedef EFI_IMAGE_IMPORT_DESCRIPTOR *PEFI_IMAGE_IMPORT_DESCRIPTOR;


//
// Defines
//
#define EFI_IMAGE_SUBSYSTEM_NATIVE						1
#define EFI_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION	16

#define IMAGE_ORDINAL_FLAG64							(0x8000000000000000)
#define IMAGE_ORDINAL_FLAG32							(0x80000000)

#define RT_VERSION										16
#define VS_VERSION_INFO									1
#define VS_FF_DEBUG										(0x00000001L)

#define IMAGE32(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
#define IMAGE64(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define HEADER_FIELD(NtHeaders, Field) (IMAGE64(NtHeaders)			\
	? ((PEFI_IMAGE_NT_HEADERS64)(NtHeaders))->OptionalHeader.Field	\
	: ((PEFI_IMAGE_NT_HEADERS32)(NtHeaders))->OptionalHeader.Field)

#define IMAGE_FIRST_SECTION(NtHeaders) ((PEFI_IMAGE_SECTION_HEADER)	\
	((UINTN)(NtHeaders) +											\
	FIELD_OFFSET(EFI_IMAGE_NT_HEADERS, OptionalHeader) +			\
	((NtHeaders))->FileHeader.SizeOfOptionalHeader))


//
// Type of file to patch
//
typedef enum _INPUT_FILETYPE
{
	Unknown,

	// BIOS boot manager/loader
	Bootmgr,	// Unsupported
	WinloadExe,	// Unsupported

	// EFI boot manager/loader
	BootmgfwEfi,
	BootmgrEfi,
	WinloadEfi,

	// Kernel
	Ntoskrnl
} INPUT_FILETYPE;


//
// Define (correct) import descriptor types and use their standard NT names because the EFI prefixed ones are taken
//

#pragma pack(push, 4) // Use 4 byte packing

typedef struct _IMAGE_IMPORT_BY_NAME
{
	UINT16 Hint;
	CHAR8 Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

#pragma pack(pop)

#pragma pack(push, 8) // 8 byte alignment for the 64 bit IAT

typedef struct _IMAGE_THUNK_DATA64
{
	union
	{
		UINT64 ForwarderString;			// UINT8* 
		UINT64 Function;				// UINT32*
		UINT64 Ordinal;
		UINT64 AddressOfData;			// PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA64, *PIMAGE_THUNK_DATA64;

#pragma pack(pop)

#pragma pack(push, 4) // Revert to 4 byte packing

typedef struct _IMAGE_THUNK_DATA32
{
	union
	{
		UINT32 ForwarderString;			// UINT8*  
		UINT32 Function;				// UINT32*
		UINT32 Ordinal;
		UINT32 AddressOfData;			// PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA32, *PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_IMPORT_DESCRIPTOR
{
	union
	{
		UINT32 Characteristics;			// 0 for terminating null import descriptor
		UINT32 OriginalFirstThunk;		// RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} u;
	UINT32 TimeDateStamp;				// 0 if not bound,
										// -1 if bound, and real date\time stamp
										//	in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
										// O.W. date/time stamp of DLL bound to (Old BIND)

	UINT32 ForwarderChain;				// -1 if no forwarders
	UINT32 Name;
	UINT32 FirstThunk;					// RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

#pragma pack(pop) // Revert to original packing


//
// Version info data
//
typedef struct _VS_FIXEDFILEINFO
{
	UINT32 dwSignature; // 0xFEEF04BD
	UINT32 dwStrucVersion;
	UINT32 dwFileVersionMS;
	UINT32 dwFileVersionLS;
	UINT32 dwProductVersionMS;
	UINT32 dwProductVersionLS;
	UINT32 dwFileFlagsMask;
	UINT32 dwFileFlags;
	UINT32 dwFileOS;
	UINT32 dwFileType;
	UINT32 dwFileSubtype;
	UINT32 dwFileDateMS;
	UINT32 dwFileDateLS;
} VS_FIXEDFILEINFO;

//
// Raw version info data as it appears in a PE file resource directory
// This struct is not in any SDK headers, not because it is super secret, but because MS
// is ashamed of it: https://docs.microsoft.com/en-gb/windows/desktop/menurc/vs-versioninfo
//
typedef struct _VS_VERSIONINFO
{
	UINT16 TotalSize;
	UINT16 DataSize;
	UINT16 Type;
	CHAR16 Name[sizeof(L"VS_VERSION_INFO") / sizeof(CHAR16)]; // Size includes null terminator
	VS_FIXEDFILEINFO FixedFileInfo;
	// Omitted: padding fields that do not contribute to TotalSize
} VS_VERSIONINFO, *PVS_VERSIONINFO;


//
// Function declarations
//
PEFI_IMAGE_NT_HEADERS
EFIAPI
RtlpImageNtHeaderEx(
	IN CONST VOID* Base,
	IN UINTN Size OPTIONAL
	);

INPUT_FILETYPE
EFIAPI
GetInputFileType(
	IN CONST UINT8 *ImageBase,
	IN UINTN ImageSize
	);

CONST CHAR16*
EFIAPI
FileTypeToString(
	IN INPUT_FILETYPE FileType
	);

VOID*
EFIAPI
GetProcedureAddress(
	IN UINTN DllBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST CHAR8* RoutineName
	);

EFI_STATUS
EFIAPI
FindIATAddressForImport(
	IN VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST CHAR8* ImportDllName,
	IN CONST CHAR8* FunctionName,
	OUT VOID **FunctionIATAddress
	);

UINT32
EFIAPI
RvaToOffset(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN UINT32 Rva
	);

VOID*
EFIAPI
RtlpImageDirectoryEntryToDataEx(
	IN CONST VOID* Base,
	IN BOOLEAN MappedAsImage,
	IN UINT16 DirectoryEntry,
	OUT UINT32 *Size
	);

EFI_STATUS
EFIAPI
FindResourceDataById(
	IN CONST VOID* ImageBase,
	IN UINT16 TypeId,
	IN UINT16 NameId,
	IN UINT16 LanguageId OPTIONAL,
	OUT VOID** ResourceData OPTIONAL,
	OUT UINT32* ResourceSize
	);

EFI_STATUS
EFIAPI
GetPeFileVersionInfo(
	IN CONST VOID* ImageBase,
	OUT UINT16* MajorVersion OPTIONAL,
	OUT UINT16* MinorVersion OPTIONAL,
	OUT UINT16* BuildNumber OPTIONAL,
	OUT UINT16* Revision OPTIONAL,
	OUT UINT32* FileFlags OPTIONAL
	);
