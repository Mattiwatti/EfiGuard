#include "EfiGuardDxe.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>


#define LDR_IS_DATAFILE(x)				(((UINTN)(x)) & (UINTN)1)
#define LDR_DATAFILE_TO_VIEW(x)			((VOID*)(((UINTN)(x)) & ~(UINTN)1))


STATIC
BOOLEAN
EFIAPI
RtlIsCanonicalAddress(
	UINTN Address
	)
{
#if defined(MDE_CPU_IA32)
	// 32-bit mode only supports 4GB max, so limits are not an issue
	return TRUE;
#elif defined(MDE_CPU_X64)
	// The most-significant 16 bits must be all 1 or all 0. (64 - 16) = 48bit linear address range.
	// 0xFFFF800000000000 = Significant 16 bits set
	// 0x0000800000000000 = 48th bit set
	return (((Address & 0xFFFF800000000000) + 0x800000000000) & ~0x800000000000) == 0;
#endif
}

PEFI_IMAGE_NT_HEADERS
EFIAPI
RtlpImageNtHeaderEx(
	IN CONST VOID* Base,
	IN UINTN Size OPTIONAL
	)
{
	CONST BOOLEAN RangeCheck = Size > 0;

	if (RangeCheck && Size < sizeof(EFI_IMAGE_DOS_HEADER))
		return NULL;
	if (((PEFI_IMAGE_DOS_HEADER)Base)->e_magic != EFI_IMAGE_DOS_SIGNATURE)
		return NULL;

	CONST UINT32 e_lfanew = ((PEFI_IMAGE_DOS_HEADER)Base)->e_lfanew;
	if (RangeCheck &&
		(e_lfanew >= Size ||
		e_lfanew >= (MAX_UINT32 - sizeof(EFI_IMAGE_NT_SIGNATURE) - sizeof(EFI_IMAGE_FILE_HEADER)) ||
		e_lfanew + sizeof(EFI_IMAGE_NT_SIGNATURE) + sizeof(EFI_IMAGE_FILE_HEADER) >= Size))
	{
		return NULL;
	}

	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = (PEFI_IMAGE_NT_HEADERS)(((UINT8*)Base) + e_lfanew);

	// On x64, verify this is a canonical address
	if (!RtlIsCanonicalAddress((UINTN)NtHeaders))
		return NULL;

	if (NtHeaders->Signature != EFI_IMAGE_NT_SIGNATURE)
		return NULL;

	return NtHeaders;
}

INPUT_FILETYPE
EFIAPI
GetInputFileType(
	IN CONST UINT8* ImageBase,
	IN UINTN ImageSize
	)
{
	// The non-EFI bootmgr starts with a 16 bit real mode stub instead of the standard MZ header
	if (*(UINT16*)ImageBase == 0xD5E9)
		return Bootmgr;

	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(ImageBase, ImageSize);
	if (NtHeaders == NULL)
		return Unknown;

	CONST UINT16 Subsystem = HEADER_FIELD(NtHeaders, Subsystem);
	if (Subsystem == EFI_IMAGE_SUBSYSTEM_NATIVE)
		return Ntoskrnl;

	if (Subsystem == EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION)
	{
		// Of the Windows loaders, only bootmgfw.efi has this subsystem type.
		// Check for the BCD Bootmgr GUID, { 9DEA862C-5CDD-4E70-ACC1-F32B344D4795 }, which is present in bootmgfw/bootmgr (and on Win >= 8 also winload.[exe|efi])
		CONST EFI_GUID BcdWindowsBootmgrGuid = { 0x9dea862c, 0x5cdd, 0x4e70, { 0xac, 0xc1, 0xf3, 0x2b, 0x34, 0x4d, 0x47, 0x95 } };
		for (UINT8* Address = (UINT8*)ImageBase; Address < ImageBase + ImageSize - sizeof(BcdWindowsBootmgrGuid); Address += sizeof(VOID*))
		{
			if (CompareGuid((CONST GUID*)Address, &BcdWindowsBootmgrGuid))
			{
				return BootmgfwEfi;
			}
		}

		// Some other OS is being booted
		return Unknown;
	}

	// All remaining known possibilities have subsystem 0x10 (Windows boot application)
	if (Subsystem != EFI_IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION)
	{
		DEBUG((DEBUG_WARN, "Unknown subsystem type 0x%02X.\r\n", Subsystem));
		return Unknown;
	}

	// Brute force scan .rsrc to check if this is either winload.efi or bootmgr.efi.
	// We've already eliminated bootmgr and bootmgfw.efi as candidates, so there will be no false positives
	UINT32 Size = 0;
	EFI_IMAGE_RESOURCE_DIRECTORY *ResourceDirTable =
		RtlpImageDirectoryEntryToDataEx(ImageBase,
										TRUE,
										EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE,
										&Size);
	if (ResourceDirTable == NULL || Size == 0)
		return Unknown;

	for (UINT8* Address = (UINT8*)ResourceDirTable; Address < ImageBase + ImageSize - sizeof(L"OSLOADER.XSL"); Address += sizeof(CHAR16))
	{
		if (CompareMem(Address, L"BOOTMGR.XSL", sizeof(L"BOOTMGR.XSL") - sizeof(CHAR16)) == 0)
		{
			return BootmgrEfi;
		}
		if (CompareMem(Address, L"OSLOADER.XSL", sizeof(L"OSLOADER.XSL") - sizeof(CHAR16)) == 0)
		{
			return WinloadEfi;
		}
	}

	// Any remaining images that could slip through here (SecConfig.efi, winresume.efi) are not relevant for us
	return Unknown;
}

CONST CHAR16*
EFIAPI
FileTypeToString(
	IN INPUT_FILETYPE FileType
	)
{
	switch (FileType)
	{
		case Bootmgr:
			return L"bootmgr";
		case WinloadExe:
			return L"winload.exe";
		case BootmgfwEfi:
			return L"bootmgfw.efi";
		case BootmgrEfi:
			return L"bootmgr.efi";
		case WinloadEfi:
			return L"winload.efi";
		case Ntoskrnl:
			return L"ntoskrnl.exe";
		case Unknown:
		default:
			return L"<unknown>";
	}
}

VOID*
EFIAPI
GetProcedureAddress(
	IN UINTN DllBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST CHAR8* RoutineName
	)
{
	if (DllBase == 0 || NtHeaders == NULL)
		return NULL;

	// Get the export directory RVA and size
	CONST PEFI_IMAGE_DATA_DIRECTORY ImageDirectories = NtHeaders->OptionalHeader.DataDirectory;
	CONST UINT32 ExportDirRva = ImageDirectories[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	CONST UINT32 ExportDirSize = ImageDirectories[EFI_IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	// Read the export directory
	CONST PEFI_IMAGE_EXPORT_DIRECTORY ExportDirectory = (PEFI_IMAGE_EXPORT_DIRECTORY)(DllBase + ExportDirRva);
	CONST UINT32* AddressOfFunctions = (UINT32*)(DllBase + ExportDirectory->AddressOfFunctions);
	CONST UINT16* AddressOfNameOrdinals = (UINT16*)(DllBase + ExportDirectory->AddressOfNameOrdinals);
	CONST UINT32* AddressOfNames = (UINT32*)(DllBase + ExportDirectory->AddressOfNames);

	// Look up the import name in the name table using a binary search
	INT32 Low = 0;
	INT32 Middle = 0;
	INT32 High = ExportDirectory->NumberOfNames - 1;

	while (High >= Low)
	{
		// Compute the next probe index and compare the import name
		Middle = (Low + High) >> 1;
		CONST INTN Result = AsciiStrCmp(RoutineName, (CHAR8*)(DllBase + AddressOfNames[Middle]));
		if (Result < 0)
			High = Middle - 1;
		else if (Result > 0)
			Low = Middle + 1;
		else
			break;
	}

	// If the high index is less than the low index, then a matching table entry
	// was not found. Otherwise, get the ordinal number from the ordinal table
	if (High < Low || Middle >= (INT32)ExportDirectory->NumberOfFunctions)
		return NULL;
	CONST UINT32 FunctionRva = AddressOfFunctions[AddressOfNameOrdinals[Middle]];
	if (FunctionRva >= ExportDirRva && FunctionRva < ExportDirRva + ExportDirSize)
		return NULL; // Ignore forward exports

	return (VOID*)(DllBase + FunctionRva);
}

EFI_STATUS
EFIAPI
FindIATAddressForImport(
	IN VOID* ImageBase,
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN CONST CHAR8* ImportDllName,
	IN CONST CHAR8* FunctionName,
	OUT VOID **FunctionIATAddress
	)
{
	*FunctionIATAddress = NULL;

	// Get the import descriptor table
	UINT32 ImportDirSize;
	CONST PIMAGE_IMPORT_DESCRIPTOR DescriptorTable =
		RtlpImageDirectoryEntryToDataEx(ImageBase,
										TRUE,
										EFI_IMAGE_DIRECTORY_ENTRY_IMPORT,
										&ImportDirSize);
	if (ImportDirSize == 0 || DescriptorTable == NULL)
		return EFI_NOT_FOUND;

	// Count the number of DLL import descriptors
	PIMAGE_IMPORT_DESCRIPTOR Entry = DescriptorTable;
	UINT32 DllCount;
	for (DllCount = 0; Entry->u.OriginalFirstThunk != 0; ++DllCount)
	{
		Entry = (PIMAGE_IMPORT_DESCRIPTOR)((UINTN)(Entry) +
			sizeof(IMAGE_IMPORT_DESCRIPTOR));
	}

	// Iterate over the import descriptors
	for (UINT32 i = 0; i < DllCount; ++i)
	{
		// Is this the import descriptor for our DLL?
		CONST PIMAGE_IMPORT_DESCRIPTOR Descriptor = &DescriptorTable[i];
		CONST CHAR8* DllName = (CHAR8*)((UINTN)ImageBase + Descriptor->Name);
		if (DllName == NULL || AsciiStriCmp(DllName, ImportDllName) != 0)
			continue; // No - skip

		// Get the thunk data using the OFT if available, otherwise use the FT
		CONST VOID* ThunkData = (VOID*)((UINTN)ImageBase +
			(Descriptor->u.OriginalFirstThunk != 0
				? Descriptor->u.OriginalFirstThunk
				: Descriptor->FirstThunk));

		// Iterate over the function imports
		if (IMAGE64(NtHeaders))
		{
			PIMAGE_THUNK_DATA64 ThunkEntry = (PIMAGE_THUNK_DATA64)ThunkData;

			for (UINT32 j = 0; ThunkEntry->u1.AddressOfData > 0; ++j)
			{
				CONST PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)(
					(UINTN)ImageBase + ThunkEntry->u1.AddressOfData);

				if ((ThunkEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG64) == 0 && // Ignore imports by ordinal
					ImportByName->Name[0] != '\0' &&
					AsciiStriCmp(ImportByName->Name, FunctionName) == 0)
				{
					// Found the import
					CONST UINT32 Rva = Descriptor->FirstThunk + j * sizeof(UINTN);
					VOID* Va = (VOID*)((UINTN)(ImageBase) + Rva);
					*FunctionIATAddress = Va;
					return EFI_SUCCESS;
				}

				ThunkEntry = (PIMAGE_THUNK_DATA64)((UINTN)ThunkEntry + sizeof(IMAGE_THUNK_DATA64));
			}
		}
		else
		{
			PIMAGE_THUNK_DATA32 ThunkEntry = (PIMAGE_THUNK_DATA32)ThunkData;

			for (UINT32 j = 0; ThunkEntry->u1.AddressOfData > 0; ++j)
			{
				CONST PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)(
					(UINTN)ImageBase + ThunkEntry->u1.AddressOfData);

				if ((ThunkEntry->u1.Ordinal & IMAGE_ORDINAL_FLAG32) == 0 && // Ignore imports by ordinal
					ImportByName->Name[0] != '\0' &&
					AsciiStriCmp(ImportByName->Name, FunctionName) == 0)
				{
					// Found the import
					CONST UINT32 Rva = Descriptor->FirstThunk + j * sizeof(UINTN);
					VOID* Va = (VOID*)((UINTN)ImageBase + Rva);
					*FunctionIATAddress = Va;
					return EFI_SUCCESS;
				}

				ThunkEntry = (PIMAGE_THUNK_DATA32)((UINTN)ThunkEntry + sizeof(IMAGE_THUNK_DATA32));
			}
		}
	}
	return EFI_NOT_FOUND;
}


UINT32
EFIAPI
RvaToOffset(
	IN PEFI_IMAGE_NT_HEADERS NtHeaders,
	IN UINT32 Rva
	)
{
	PEFI_IMAGE_SECTION_HEADER SectionHeaders = IMAGE_FIRST_SECTION(NtHeaders);
	CONST UINT16 NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
	UINT32 Result = 0;
	for (UINT16 i = 0; i < NumberOfSections; ++i)
	{
		if (SectionHeaders->VirtualAddress <= Rva &&
			SectionHeaders->VirtualAddress + SectionHeaders->Misc.VirtualSize > Rva)
		{
			Result = Rva - SectionHeaders->VirtualAddress +
							SectionHeaders->PointerToRawData;
			break;
		}
		SectionHeaders++;
	}
	return Result;
}

// The kernel and ntdll divide this into [ RtlImageDirectoryEntryToData -> RtlpImageDirectoryEntryToData ->
// { RtlpImageDirectoryEntryToData32 / RtlpImageDirectoryEntryToData64 } -> RtlpAddressInSectionTable ->
// RtlpSectionTableFromVirtualAddress ], but with some macro help and RvaToOffset it can be limited to one function
VOID*
EFIAPI
RtlpImageDirectoryEntryToDataEx(
	IN CONST VOID* Base,
	IN BOOLEAN MappedAsImage,
	IN UINT16 DirectoryEntry,
	OUT UINT32 *Size
	)
{
	if (LDR_IS_DATAFILE(Base))
	{
		Base = LDR_DATAFILE_TO_VIEW(Base);
		MappedAsImage = FALSE;
	}

	CONST PEFI_IMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(Base, 0);
	if (NtHeaders == NULL)
		return NULL;

	if (DirectoryEntry >= HEADER_FIELD(NtHeaders, NumberOfRvaAndSizes))
		return NULL;

	CONST PEFI_IMAGE_DATA_DIRECTORY Directories = HEADER_FIELD(NtHeaders, DataDirectory);
	CONST UINT32 Rva = Directories[DirectoryEntry].VirtualAddress;
	if (Rva == 0)
		return NULL;

	// Omitted: check for illegal UM <-> KM boundary crossing as it is N/A for us

	*Size = Directories[DirectoryEntry].Size;
	if (MappedAsImage || Rva < HEADER_FIELD(NtHeaders, SizeOfHeaders))
	{
		return (UINT8*)(Base) + Rva;
	}

	return (UINT8*)(Base) + RvaToOffset(NtHeaders, Rva);
}

// Similar to LdrFindResource_U + LdrAccessResource combined, with some shortcuts for size optimization:
// - Only IDs are supported for type/name/language, not strings. Named entries ("MUI", "RCDATA", ...) are ignored.
// - Only images are supported, not mapped data files (e.g. LoadLibrary(..., LOAD_LIBRARY_AS_DATAFILE) data).
// - Language ID matching is greatly simplified. Either supply 0 (first entry wins) or an exact match ID. There are no fallbacks for similar languages, user preferences, etc.
// - The path length is assumed to always be 3: Type -> Name -> Language, with a data entry as leaf node.
//
// NB: The output will be a direct pointer to the resource data, which on Windows usually means it is read only, and on UEFI
// means writing to it is probably not what you want. This is the same behaviour as LdrAccessResource() but easy to forget.
// If you need to modify the data or unload the original image at some point, copy the data first.
EFI_STATUS
EFIAPI
FindResourceDataById(
	IN CONST VOID* ImageBase,
	IN UINT16 TypeId,
	IN UINT16 NameId,
	IN UINT16 LanguageId OPTIONAL,
	OUT VOID** ResourceData OPTIONAL,
	OUT UINT32* ResourceSize
	)
{
	if (ResourceData != NULL)
		*ResourceData = NULL;
	*ResourceSize = 0;

	ASSERT((!LDR_IS_DATAFILE(ImageBase)));

	UINT32 Size = 0;
	EFI_IMAGE_RESOURCE_DIRECTORY *ResourceDirTable =
		RtlpImageDirectoryEntryToDataEx(ImageBase,
										TRUE,
										EFI_IMAGE_DIRECTORY_ENTRY_RESOURCE,
										&Size);
	if (ResourceDirTable == NULL || Size == 0)
		return EFI_NOT_FOUND;

	CONST UINT8* ResourceDirVa = (UINT8*)ResourceDirTable;
	EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY *DirEntry = NULL;
	for (UINT16 i = ResourceDirTable->NumberOfNamedEntries; i < ResourceDirTable->NumberOfNamedEntries + ResourceDirTable->NumberOfIdEntries; ++i)
	{
		DirEntry = (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY*)((UINT8*)ResourceDirTable + sizeof(EFI_IMAGE_RESOURCE_DIRECTORY) + (i * sizeof(EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY)));
		if ((BOOLEAN)DirEntry->u1.s.NameIsString)
			continue;
		if (DirEntry->u1.Id == TypeId && DirEntry->u2.s.DataIsDirectory)
			break;
	}
	if (DirEntry == NULL || DirEntry->u1.Id != TypeId)
		return EFI_NOT_FOUND;

	ResourceDirTable = (EFI_IMAGE_RESOURCE_DIRECTORY*)(ResourceDirVa + DirEntry->u2.s.OffsetToDirectory);
	DirEntry = NULL;
	for (UINT16 i = ResourceDirTable->NumberOfNamedEntries; i < ResourceDirTable->NumberOfNamedEntries + ResourceDirTable->NumberOfIdEntries; ++i)
	{
		DirEntry = (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY*)((UINT8*)ResourceDirTable + sizeof(EFI_IMAGE_RESOURCE_DIRECTORY) + (i * sizeof(EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY)));
		if ((BOOLEAN)DirEntry->u1.s.NameIsString)
			continue;
		if (DirEntry->u1.Id == NameId && DirEntry->u2.s.DataIsDirectory)
			break;
	}
	if (DirEntry == NULL || DirEntry->u1.Id != NameId)
		return EFI_NOT_FOUND;

	ResourceDirTable = (EFI_IMAGE_RESOURCE_DIRECTORY*)(ResourceDirVa + DirEntry->u2.s.OffsetToDirectory);
	DirEntry = NULL;
	for (UINT16 i = ResourceDirTable->NumberOfNamedEntries; i < ResourceDirTable->NumberOfNamedEntries + ResourceDirTable->NumberOfIdEntries; ++i)
	{
		DirEntry = (EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY*)((UINT8*)ResourceDirTable + sizeof(EFI_IMAGE_RESOURCE_DIRECTORY) + (i * sizeof(EFI_IMAGE_RESOURCE_DIRECTORY_ENTRY)));
		if ((BOOLEAN)DirEntry->u1.s.NameIsString)
			continue;
		if ((LanguageId == 0 || DirEntry->u1.Id == LanguageId) && !DirEntry->u2.s.DataIsDirectory)
			break;
	}
	if (DirEntry == NULL || (LanguageId != 0 && DirEntry->u1.Id != LanguageId))
		return EFI_INVALID_LANGUAGE;

	EFI_IMAGE_RESOURCE_DATA_ENTRY *DataEntry = (EFI_IMAGE_RESOURCE_DATA_ENTRY*)(ResourceDirVa + DirEntry->u2.OffsetToData);
	if (ResourceData != NULL)
		*ResourceData = (VOID*)((UINT8*)ImageBase + DataEntry->OffsetToData);
	*ResourceSize = DataEntry->Size;

	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
GetPeFileVersionInfo(
	IN CONST VOID* ImageBase,
	OUT UINT16* MajorVersion OPTIONAL,
	OUT UINT16* MinorVersion OPTIONAL,
	OUT UINT16* BuildNumber OPTIONAL,
	OUT UINT16* Revision OPTIONAL,
	OUT UINT32* FileFlags OPTIONAL
	)
{
	// Search the PE file's resource directory (if it exists) for a version info entry
	VS_VERSIONINFO *VersionResource;
	UINT32 VersionResourceSize;
	CONST EFI_STATUS Status = FindResourceDataById(ImageBase,
													RT_VERSION,
													VS_VERSION_INFO,
													MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),
													(VOID**)&VersionResource,
													&VersionResourceSize);
	if (EFI_ERROR(Status))
	{
		DEBUG((DEBUG_ERROR, "GetPeFileVersionInfo: FindResourceDataById returned %llx\r\n", Status));
		return Status; // Either no resource directory or no version info. Perhaps ASSERT() here as the files we patch should always have them
	}

	if (VersionResourceSize < sizeof(VS_VERSIONINFO) ||
		StrnCmp(VersionResource->Name, L"VS_VERSION_INFO", (sizeof(L"VS_VERSION_INFO") / sizeof(CHAR16)) - 1) != 0 ||
		VersionResource->FixedFileInfo.dwSignature != 0xFEEF04BD)
	{
		DEBUG((DEBUG_ERROR, "GetPeFileVersionInfo: RESOURCE_VERSION_DATA at 0x%p is not valid\r\n", (VOID*)VersionResource));
		return EFI_NOT_FOUND;
	}

	if (MajorVersion != NULL)
		*MajorVersion = HIWORD(VersionResource->FixedFileInfo.dwFileVersionMS);
	if (MinorVersion != NULL)
		*MinorVersion = LOWORD(VersionResource->FixedFileInfo.dwFileVersionMS);
	if (BuildNumber != NULL)
		*BuildNumber = HIWORD(VersionResource->FixedFileInfo.dwFileVersionLS);
	if (Revision != NULL)
		*Revision = LOWORD(VersionResource->FixedFileInfo.dwFileVersionLS);
	if (FileFlags != NULL)
		*FileFlags = (VersionResource->FixedFileInfo.dwFileFlags & VersionResource->FixedFileInfo.dwFileFlagsMask);

	return EFI_SUCCESS;
}
