#include "EfiDSEFix.h"
#include <ntstatus.h>

NTSTATUS
DumpSystemInformation(
	)
{
	SYSTEM_BOOT_ENVIRONMENT_INFORMATION BootInfo = { 0 };
	NTSTATUS Status = NtQuerySystemInformation(SystemBootEnvironmentInformation,
												&BootInfo,
												sizeof(BootInfo),
												nullptr);
	if (!NT_SUCCESS(Status))
		Printf(L"SystemBootEnvironmentInformation: error %08X\n\n", Status);
	else
	{
		Printf(L"SystemBootEnvironmentInformation:\n\t- BootIdentifier: ");
		PrintGuid(BootInfo.BootIdentifier);
		Printf(L"\n\t- FirmwareType: %s\n\t- BootFlags: 0x%llX\n\n",
			(BootInfo.FirmwareType == FirmwareTypeUefi ? L"UEFI" : L"BIOS"), BootInfo.BootFlags);
	}

	ULONG Size = 0;
	Status = NtQuerySystemInformation(SystemModuleInformation,
										nullptr,
										0,
										&Size);
	if (Status != STATUS_INFO_LENGTH_MISMATCH)
		Printf(L"SystemModuleInformation: %08X\n\n", Status);
	else
	{
		const PRTL_PROCESS_MODULES ModuleInfo = static_cast<PRTL_PROCESS_MODULES>(
			RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, 2 * static_cast<SIZE_T>(Size)));
		Status = NtQuerySystemInformation(SystemModuleInformation,
										ModuleInfo,
										2 * Size,
										nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemModuleInformation: %08X\n\n", Status);
		else
		{
			const RTL_PROCESS_MODULE_INFORMATION Ntoskrnl = ModuleInfo->Modules[0];
			Printf(L"SystemModuleInformation:\n\t- Kernel: %S (%S)\n\n",
				reinterpret_cast<PCCH>(Ntoskrnl.FullPathName + Ntoskrnl.OffsetToFileName),
				reinterpret_cast<PCCH>(Ntoskrnl.FullPathName));
		}
		RtlFreeHeap(RtlProcessHeap(), 0, ModuleInfo);
	}

	SYSTEM_CODEINTEGRITY_INFORMATION CodeIntegrityInfo = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
	Status = NtQuerySystemInformation(SystemCodeIntegrityInformation,
										&CodeIntegrityInfo,
										sizeof(CodeIntegrityInfo),
										nullptr);
	if (!NT_SUCCESS(Status))
		Printf(L"SystemCodeIntegrityInformation: error %08X\n\n", Status);
	else
		Printf(L"SystemCodeIntegrityInformation:\n\t- IntegrityOptions: 0x%04X\n\n",
			CodeIntegrityInfo.CodeIntegrityOptions);

	SYSTEM_KERNEL_DEBUGGER_INFORMATION KernelDebuggerInfo = { 0 };
	Status = NtQuerySystemInformation(SystemKernelDebuggerInformation,
										&KernelDebuggerInfo,
										sizeof(KernelDebuggerInfo),
										nullptr);
	if (!NT_SUCCESS(Status))
		Printf(L"SystemKernelDebuggerInformation: error %08X\n\n", Status);
	else
		Printf(L"SystemKernelDebuggerInformation:\n\t- KernelDebuggerEnabled: %u\n\t- KernelDebuggerNotPresent: %u\n\n",
			KernelDebuggerInfo.KernelDebuggerEnabled, KernelDebuggerInfo.KernelDebuggerNotPresent);

	if ((RtlNtMajorVersion() >= 6 && RtlNtMinorVersion() >= 3) || RtlNtMajorVersion() > 6)
	{
		SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX KernelDebuggerInfoEx = { 0 };
		Status = NtQuerySystemInformation(SystemKernelDebuggerInformationEx,
											&KernelDebuggerInfoEx,
											sizeof(KernelDebuggerInfoEx),
											nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemKernelDebuggerInformationEx: error %08X\n\n", Status);
		else
			Printf(L"SystemKernelDebuggerInformationEx:\n\t- DebuggerAllowed: %u\n\t- DebuggerEnabled: %u\n\t- DebuggerPresent: %u\n\n",
				KernelDebuggerInfoEx.DebuggerAllowed, KernelDebuggerInfoEx.DebuggerEnabled, KernelDebuggerInfoEx.DebuggerPresent);
	}

	const UCHAR KdDebuggerEnabled = SharedUserData->KdDebuggerEnabled;
	Printf(L"SharedUserData->KdDebuggerEnabled: 0x%02X\n\n", KdDebuggerEnabled);

	if (RtlNtMajorVersion() > 6)
	{
		UCHAR KernelDebuggerFlags = 0;
		Status = NtQuerySystemInformation(SystemKernelDebuggerFlags,
											&KernelDebuggerFlags,
											sizeof(KernelDebuggerFlags),
											nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemKernelDebuggerFlags: error %08X\n\n", Status);
		else
			Printf(L"SystemKernelDebuggerFlags: 0x%02X\n\n", KernelDebuggerFlags);

		SYSTEM_CODEINTEGRITYPOLICY_INFORMATION CodeIntegrityPolicyInfo = { 0 };
		Status = NtQuerySystemInformation(SystemCodeIntegrityPolicyInformation,
											&CodeIntegrityPolicyInfo,
											sizeof(CodeIntegrityPolicyInfo),
											nullptr);
		if (!NT_SUCCESS(Status))
			Printf(L"SystemCodeIntegrityPolicyInformation: error %08X\n\n", Status);
		else
			Printf(L"SystemCodeIntegrityPolicyInformation:\n\t- Options: 0x%04X\n\t- HVCIOptions: 0x%04X\n\n",
				CodeIntegrityPolicyInfo.Options, CodeIntegrityPolicyInfo.HVCIOptions);
	}

	return Status;
}
