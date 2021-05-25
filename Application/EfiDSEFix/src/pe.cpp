#include "EfiDSEFix.h"
#include <ntstatus.h>

#define IMAGE32(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
#define IMAGE64(NtHeaders) ((NtHeaders)->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

#define HEADER_FIELD(NtHeaders, Field) (IMAGE64(NtHeaders) \
	? ((PIMAGE_NT_HEADERS64)(NtHeaders))->OptionalHeader.Field \
	: ((PIMAGE_NT_HEADERS32)(NtHeaders))->OptionalHeader.Field)

static
NTSTATUS
RtlOpenFile(
	_Out_ PHANDLE FileHandle,
	_In_ PCWCHAR Filename
	)
{
	*FileHandle = nullptr;

	UNICODE_STRING NtPath;
	RTL_RELATIVE_NAME_U RelativeName;
	NTSTATUS Status = RtlDosPathNameToRelativeNtPathName_U_WithStatus(const_cast<PWCHAR>(Filename),
																	&NtPath,
																	nullptr,
																	&RelativeName);
	if (!NT_SUCCESS(Status))
		return Status;

	const BOOLEAN PathIsRelative = RelativeName.RelativeName.Length > 0;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	InitializeObjectAttributes(&ObjectAttributes,
								PathIsRelative ? &RelativeName.RelativeName : &NtPath,
								OBJ_CASE_INSENSITIVE,
								PathIsRelative ? RelativeName.ContainingDirectory : nullptr,
								nullptr);
	Status = NtCreateFile(FileHandle,
						FILE_GENERIC_READ | SYNCHRONIZE,
						&ObjectAttributes,
						&IoStatusBlock,
						nullptr,
						FILE_ATTRIBUTE_NORMAL,
						FILE_SHARE_READ,
						FILE_OPEN,
						FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
						nullptr,
						0);

	RtlFreeHeap(RtlProcessHeap(), 0, NtPath.Buffer);
	RtlReleaseRelativeName(&RelativeName);

	return Status;
}

NTSTATUS
MapFileSectionView(
	_In_ PCWCHAR Filename,
	_Out_ PVOID *ImageBase,
	_Out_ PSIZE_T ViewSize
	)
{
	*ImageBase = nullptr;
	*ViewSize = 0;

	// Open the file
	HANDLE FileHandle;
	NTSTATUS Status = RtlOpenFile(&FileHandle, Filename);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"NtCreateFile: 0x%08X\n", Status);
		return Status;
	}

	// Obtain a section handle
	HANDLE SectionHandle;
	Status = NtCreateSection(&SectionHandle,
							STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ,
							nullptr,
							nullptr,
							PAGE_READONLY,
							SEC_IMAGE,
							FileHandle);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"NtCreateSection: 0x%08X\n", Status);
		NtClose(FileHandle);
		return Status;
	}

	// Map a read only section view
	Status = NtMapViewOfSection(SectionHandle,
								NtCurrentProcess,
								ImageBase,
								0,
								0,
								nullptr,
								ViewSize,
								ViewUnmap,
								0,
								PAGE_READONLY);
	
	if (Status == STATUS_IMAGE_NOT_AT_BASE)
		Status = STATUS_SUCCESS;
	if (!NT_SUCCESS(Status))
		Printf(L"NtMapViewOfSection: 0x%08X\n", Status);

	NtClose(SectionHandle);
	NtClose(FileHandle);

	return Status;
}

BOOLEAN
AddressIsInSection(
	_In_ PUCHAR ImageBase,
	_In_ PUCHAR Address,
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ PCCH SectionName
	)
{
	if (ImageBase > Address)
		return FALSE;
	if (Address >= ImageBase + NtHeaders->OptionalHeader.SizeOfImage)
		return FALSE;

	const ULONG Rva = static_cast<ULONG>(static_cast<ULONG_PTR>(Address - ImageBase));
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	const USHORT NumberOfSections = NtHeaders->FileHeader.NumberOfSections;
	for (USHORT i = 0; i < NumberOfSections; ++i)
	{
		if (Section->VirtualAddress <= Rva &&
			Section->VirtualAddress + Section->Misc.VirtualSize > Rva)
		{
			if (strncmp(reinterpret_cast<PCCH>(Section->Name), SectionName, IMAGE_SIZEOF_SHORT_NAME) == 0)
				return TRUE;
		}
		Section++;
	}
	return FALSE;
}

PVOID
GetProcedureAddress(
	_In_ ULONG_PTR DllBase,
	_In_ PCCH RoutineName
	)
{
	// Find and verify PE headers
	const PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(DllBase);
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return nullptr;
	const PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(DllBase + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return nullptr;

	// Get the export directory RVA and size
	const PIMAGE_DATA_DIRECTORY ImageDirectories = HEADER_FIELD(NtHeaders, DataDirectory);
	const ULONG ExportDirRva = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const ULONG ExportDirSize = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	// Read the export directory
	const PIMAGE_EXPORT_DIRECTORY ExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(DllBase + ExportDirRva);
	const PULONG AddressOfFunctions = reinterpret_cast<PULONG>(DllBase + ExportDirectory->AddressOfFunctions);
	const PUSHORT AddressOfNameOrdinals = reinterpret_cast<PUSHORT>(DllBase + ExportDirectory->AddressOfNameOrdinals);
	const PULONG AddressOfNames = reinterpret_cast<PULONG>(DllBase + ExportDirectory->AddressOfNames);

	// Look up the import name in the name table using a binary search
	LONG Low = 0;
	LONG Middle = 0;
	LONG High = ExportDirectory->NumberOfNames - 1;

	while (High >= Low)
	{
		// Compute the next probe index and compare the import name
		Middle = (Low + High) >> 1;
		const LONG Result = strcmp(RoutineName, reinterpret_cast<PCHAR>(DllBase + AddressOfNames[Middle]));
		if (Result < 0)
			High = Middle - 1;
		else if (Result > 0)
			Low = Middle + 1;
		else
			break;
	}

	// If the high index is less than the low index, then a matching table entry
	// was not found. Otherwise, get the ordinal number from the ordinal table
	if (High < Low || Middle >= static_cast<LONG>(ExportDirectory->NumberOfFunctions))
		return nullptr;
	const ULONG FunctionRva = AddressOfFunctions[AddressOfNameOrdinals[Middle]];
	if (FunctionRva >= ExportDirRva && FunctionRva < ExportDirRva + ExportDirSize)
		return nullptr; // Ignore forwarded exports

	return reinterpret_cast<PVOID>(DllBase + FunctionRva);
}
