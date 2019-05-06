/*++ BUILD Version: 0011 // Increment this if a change has global effects

Copyright (c) Microsoft Corporation. All rights reserved.

Module Name:

	arc.h

Abstract:

	This header file defines the ARC system firmware interface and the
	NT structures that are dependent on ARC types.

	This module may not contain any definitions that are exposed in
	public kit headers.

Author:

	David N. Cutler (davec) 18-May-1991

Revision History:

	James E. Moe (jamoe) 23-Jan-2003
		Public/Private header split

--*/

//
// Despite the notice above, this file was 'exposed in public kit headers' in the Windows 10.0.10586.0 WDK. Oops.
// Some of these types also (re)appear seemingly at random in public PDBs, notably 10.0.17134.0+ and the Windows 7 ones.
// Much more info at https://www.geoffchappell.com/studies/windows/km/ntoskrnl/structs/loader_parameter_block.htm
//

#pragma once

#include "ntdef.h"

//
// Define configuration routine types.
//
// Configuration information.
//
typedef enum _CONFIGURATION_TYPE {
	ArcSystem,
	CentralProcessor,
	FloatingPointProcessor,
	PrimaryIcache,
	PrimaryDcache,
	SecondaryIcache,
	SecondaryDcache,
	SecondaryCache,
	EisaAdapter,
	TcAdapter,
	ScsiAdapter,
	DtiAdapter,
	MultiFunctionAdapter,
	DiskController,
	TapeController,
	CdromController,
	WormController,
	SerialController,
	NetworkController,
	DisplayController,
	ParallelController,
	PointerController,
	KeyboardController,
	AudioController,
	OtherController,
	DiskPeripheral,
	FloppyDiskPeripheral,
	TapePeripheral,
	ModemPeripheral,
	MonitorPeripheral,
	PrinterPeripheral,
	PointerPeripheral,
	KeyboardPeripheral,
	TerminalPeripheral,
	OtherPeripheral,
	LinePeripheral,
	NetworkPeripheral,
	SystemMemory,
	DockingInformation,
	RealModeIrqRoutingTable,
	RealModePCIEnumeration,
	MaximumType
} CONFIGURATION_TYPE, *PCONFIGURATION_TYPE;

//
// Profile information stored in the registry, read from cmboot, and presented
// to the loader.
//
#define HW_PROFILE_STATUS_SUCCESS			0x0000
#define HW_PROFILE_STATUS_ALIAS_MATCH		0x0001
#define HW_PROFILE_STATUS_TRUE_MATCH		0x0002
#define HW_PROFILE_STATUS_PRISTINE_MATCH	0x0003
#define HW_PROFILE_STATUS_FAILURE			0xC001

//
// Docking States for the given profile
//
#define HW_PROFILE_DOCKSTATE_UNSUPPORTED	(0x0)
#define HW_PROFILE_DOCKSTATE_UNDOCKED		(0x1)
#define HW_PROFILE_DOCKSTATE_DOCKED			(0x2)
#define HW_PROFILE_DOCKSTATE_UNKNOWN		(0x3)
#define HW_PROFILE_DOCKSTATE_USER_SUPPLIED	(0x4)
#define HW_PROFILE_DOCKSTATE_USER_UNDOCKED		\
			(HW_PROFILE_DOCKSTATE_USER_SUPPLIED | HW_PROFILE_DOCKSTATE_UNDOCKED)
#define HW_PROFILE_DOCKSTATE_USER_DOCKED		\
			(HW_PROFILE_DOCKSTATE_USER_SUPPLIED | HW_PROFILE_DOCKSTATE_DOCKED)

//
// Capabilites of the given profile
//
#define HW_PROFILE_CAPS_VCR					0x0001 // As apposed to Surprize
#define HW_PROFILE_CAPS_DOCKING_WARM		0x0002
#define HW_PROFILE_CAPS_DOCKING_HOT			0x0004
#define HW_PROFILE_CAPS_RESERVED			0xFFF8

//
// Extension structure to the LOADER_PARAMETER_BLOCK in arc.h
//
typedef struct _PROFILE_PARAMETER_BLOCK {
	UINT16 Status;
	UINT16 Reserved;
	UINT16 DockingState;
	UINT16 Capabilities;
	UINT32 DockID;
	UINT32 SerialNumber;
} PROFILE_PARAMETER_BLOCK;

//
// Block to communcation the current ACPI docking state
//
typedef struct _PROFILE_ACPI_DOCKING_STATE {
	UINT16 DockingState;
	UINT16 SerialLength;
	CHAR16 SerialNumber[1];
} PROFILE_ACPI_DOCKING_STATE, *PPROFILE_ACPI_DOCKING_STATE;

//
// Define ARC_STATUS type.
//
typedef UINT32 ARC_STATUS;

//
// Define configuration routine types.
//
// Configuration information.
//
typedef enum _CONFIGURATION_CLASS {
	SystemClass,
	ProcessorClass,
	CacheClass,
	AdapterClass,
	ControllerClass,
	PeripheralClass,
	MemoryClass,
	MaximumClass
} CONFIGURATION_CLASS, *PCONFIGURATION_CLASS;

//
// Define DEVICE_FLAGS
//
typedef struct _DEVICE_FLAGS {
	UINT32 Failed : 1;
	UINT32 ReadOnly : 1;
	UINT32 Removable : 1;
	UINT32 ConsoleIn : 1;
	UINT32 ConsoleOut : 1;
	UINT32 Input : 1;
	UINT32 Output : 1;
} DEVICE_FLAGS, *PDEVICE_FLAGS;

typedef struct _CONFIGURATION_COMPONENT {
	CONFIGURATION_CLASS Class;
	CONFIGURATION_TYPE Type;
	DEVICE_FLAGS Flags;
	UINT16 Version;
	UINT16 Revision;
	UINT32 Key;
	union {
		UINT32 AffinityMask;
		struct {
			UINT16 Group;
			UINT16 GroupIndex;
		} s;
	} u;
	UINT32 ConfigurationDataLength;
	UINT32 IdentifierLength;
	CHAR8* Identifier;
} CONFIGURATION_COMPONENT, *PCONFIGURATION_COMPONENT;

//
// Define configuration data structure used in all systems.
//
typedef struct _CONFIGURATION_COMPONENT_DATA {
	struct _CONFIGURATION_COMPONENT_DATA *Parent;
	struct _CONFIGURATION_COMPONENT_DATA *Child;
	struct _CONFIGURATION_COMPONENT_DATA *Sibling;
	CONFIGURATION_COMPONENT ComponentEntry;
	VOID* ConfigurationData;
} CONFIGURATION_COMPONENT_DATA, *PCONFIGURATION_COMPONENT_DATA;

//
// Define memory allocation structures used in all systems.
//
typedef enum _TYPE_OF_MEMORY {
	LoaderExceptionBlock,								// 0
	LoaderSystemBlock,									// 1
	LoaderFree,											// 2
	LoaderBad,											// 3
	LoaderLoadedProgram,								// 4
	LoaderFirmwareTemporary,							// 5
	LoaderFirmwarePermanent,							// 6
	LoaderOsloaderHeap,									// 7
	LoaderOsloaderStack,								// 8
	LoaderSystemCode,									// 9
	LoaderHalCode,										// a
	LoaderBootDriver,									// b
	LoaderConsoleInDriver,								// c
	LoaderConsoleOutDriver,								// d
	LoaderStartupDpcStack,								// e
	LoaderStartupKernelStack,							// f
	LoaderStartupPanicStack,							// 10
	LoaderStartupPcrPage,								// 11
	LoaderStartupPdrPage,								// 12
	LoaderRegistryData,									// 13
	LoaderMemoryData,									// 14
	LoaderNlsData,										// 15
	LoaderSpecialMemory,								// 16
	LoaderBBTMemory,									// 17
	LoaderZero,											// 18
	LoaderXIPRom,										// 19
	LoaderHALCachedMemory,								// 1a
	LoaderLargePageFiller,								// 1b
	LoaderErrorLogMemory,								// 1c
	LoaderVsmMemory,									// 1d
	LoaderFirmwareCode,									// 1e
	LoaderFirmwareData,									// 1f
	LoaderFirmwareReserved,								// 20
	LoaderEnclaveMemory,								// 21
	LoaderFirmwareKsr,									// 22
	LoaderEnclaveKsr,									// 23
	LoaderSkMemory,										// 24
	LoaderSkFirmwareReserved,							// 25
	LoaderIoSpaceMemoryZeroed,							// 26
	LoaderIoSpaceMemoryFree,							// 27
	LoaderIoSpaceMemoryKsr,								// 28
	LoaderMaximum,										// 29
} TYPE_OF_MEMORY;

typedef struct _MEMORY_ALLOCATION_DESCRIPTOR {
	LIST_ENTRY ListEntry;
	TYPE_OF_MEMORY MemoryType;
	UINTN BasePage;
	UINTN PageCount;
} MEMORY_ALLOCATION_DESCRIPTOR, *PMEMORY_ALLOCATION_DESCRIPTOR;

//
// Define loader parameter block structure.
//
typedef struct _NLS_DATA_BLOCK {
	VOID* AnsiCodePageData;
	VOID* OemCodePageData;
	VOID* UnicodeCaseTableData;
} NLS_DATA_BLOCK, *PNLS_DATA_BLOCK;

typedef struct _VHD_DISK_SIGNATURE {
	UINT32 ParentPartitionNumber;
	UINT8 BootDevice[ANYSIZE_ARRAY];
} VHD_DISK_SIGNATURE, *PVHD_DISK_SIGNATURE;

typedef struct _ARC_DISK_SIGNATURE {
	LIST_ENTRY ListEntry;
	UINT32 Signature;
	CHAR8* ArcName;
	UINT32 CheckSum;
	BOOLEAN ValidPartitionTable;
	BOOLEAN xInt13;
	BOOLEAN IsGpt;
	UINT8 Reserved;
	UINT8 GptSignature[16];
	PVHD_DISK_SIGNATURE VhdSignature;
} ARC_DISK_SIGNATURE, *PARC_DISK_SIGNATURE;

typedef struct _ARC_DISK_INFORMATION {
	LIST_ENTRY DiskSignatures;
} ARC_DISK_INFORMATION, *PARC_DISK_INFORMATION;

typedef struct _I386_LOADER_BLOCK {

#if defined(_X86_) || defined(_AMD64_)
	VOID* CommonDataArea;
	UINT32 MachineType;	// Temporary only
	UINT32 VirtualBias;
#else
	UINT32 PlaceHolder;
#endif

} I386_LOADER_BLOCK, *PI386_LOADER_BLOCK;

typedef struct _ARM_LOADER_BLOCK {

#if defined(_ARM_) || defined(_ARM64_)
	UINTN VirtualBias;
	VOID* KdCpuBuffer;
#else
	UINT32 PlaceHolder;
#endif

} ARM_LOADER_BLOCK, *PARM_LOADER_BLOCK;

#define NUMBER_OF_LOADER_TR_ENTRIES 8

typedef struct _LOADER_PERFORMANCE_DATA {
	UINT64 StartTime;
	UINT64 EndTime;

	//
	// Below added in 10.0.17763.0
	//
	UINT64 PreloadEndTime;
	UINT64 TcbLoaderStartTime;
	UINT64 LoadHypervisorTime;
	UINT64 LaunchHypervisorTime;
	UINT64 LoadVsmTime;
	UINT64 LaunchVsmTime;

	//
	// Below added in 10.0.18362.0
	//
	UINT64 ExecuteTransitionStartTime;
	UINT64 ExecuteTransitionEndTime;
	UINT64 LoadDriversTime;
	UINT64 CleanupVsmTime;
} LOADER_PERFORMANCE_DATA, *PLOADER_PERFORMANCE_DATA;

//
// Entropy result codes and source IDs
// for Boot entropy sources are defined both in arc.h and
// ntexapi.h. These two copies must be kept identical.
//
typedef enum _BOOT_ENTROPY_SOURCE_RESULT_CODE {
	BootEntropySourceStructureUninitialized = 0,
	BootEntropySourceDisabledByPolicy = 1,
	BootEntropySourceNotPresent = 2,
	BootEntropySourceError = 3,
	BootEntropySourceSuccess = 4,
} BOOT_ENTROPY_SOURCE_RESULT_CODE, *PBOOT_ENTROPY_SOURCE_RESULT_CODE;

typedef enum _BOOT_ENTROPY_SOURCE_ID {
	BootEntropySourceNone = 0,
	BootEntropySourceSeedfile = 1,
	BootEntropySourceExternal = 2,
	BootEntropySourceTpm = 3,
	BootEntropySourceRdrand = 4,
	BootEntropySourceTime = 5,
	BootEntropySourceAcpiOem0 = 6,
	BootEntropySourceUefi = 7,
	BootEntropySourceCng = 8,
	BootEntropySourceTcbTpm = 9,
	BootEntropySourceTcbRdrand = 10,
	BootMaxEntropySources = 10,
} BOOT_ENTROPY_SOURCE_ID;

//
// The SORTPP tool can't handle array sizes expressed in terms of enums
// This hack can be removed when the tool is fixed
//
#define BootMaxEntropySources			(10)

#define BOOT_ENTROPY_SOURCE_DATA_SIZE	(64)
#define BOOT_RNG_BYTES_FOR_NTOSKRNL		(1024)
#define BOOT_SEED_BYTES_FOR_CNG			(48)

//
// The boot environment uses the following bytes from the ntoskrnl RNG data
// region. The kernel should consider the first
// BOOT_BL_NTOSKRNL_RNG_BYTES_USED bytes already consumed.
//
#define BOOT_BL_NTOSKRNL_RNG_BYTES_USED (55 * sizeof(UINT32))

//
// Boot entropy information
// This is the data that Boot passes to NT that contains the
// entropy & RNG information.
// These are the Boot versions of these structures.
// The name contains the string 'LDR' to distinguish it from the
// OS loader equivalents in ntexapi_h.w
//
typedef struct _BOOT_ENTROPY_SOURCE_LDR_RESULT {
	BOOT_ENTROPY_SOURCE_ID SourceId;
	UINT64 Policy;
	BOOT_ENTROPY_SOURCE_RESULT_CODE ResultCode;
	NTSTATUS ResultStatus;
	UINT64 Time; // in BlArchGetPerformanceCounter() units
	UINT32 EntropyLength;
	UINT8 EntropyData[BOOT_ENTROPY_SOURCE_DATA_SIZE];
} BOOT_ENTROPY_SOURCE_LDR_RESULT, *PBOOT_ENTROPY_SOURCE_LDR_RESULT;

//
// EFI Offline crashdump configuration table definition.
//
#define OFFLINE_CRASHDUMP_VERSION_1 1
#define OFFLINE_CRASHDUMP_VERSION_2 2
#define OFFLINE_CRASHDUMP_VERSION_MAX OFFLINE_CRASHDUMP_VERSION_2

typedef struct _OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2 {
	UINT32 Version;
	UINT32 AbnormalResetOccurred;
	UINT32 OfflineMemoryDumpCapable;

	//
	// Version_2 additional members.
	//
	PHYSICAL_ADDRESS ResetDataAddress;
	UINT32 ResetDataSize;
} OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2, *POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2;

//
// Original first version definition. Now only used in winload.efi when interfacing with firmware, and in
// sysinfo.c when interfacing with higher level sw above the kernel, to maintain backward compatibility.
//
typedef struct _OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1 {
	UINT32 Version;
	UINT32 AbnormalResetOccurred;
	UINT32 OfflineMemoryDumpCapable;
} OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1, *POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V1;

typedef OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2 OFFLINE_CRASHDUMP_CONFIGURATION_TABLE;
typedef POFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2 POFFLINE_CRASHDUMP_CONFIGURATION_TABLE;

//
// The constant BootMaxEntropySources is defined both in arc.w and ntexapi_h.w.
// If these ever get out of sync, different components will disagree on the value,
// and thus on the size of the array below.
// To help detect this type of bug we add a field with this constant so that the
// CHKed builds can assert on it.
//
typedef struct _BOOT_ENTROPY_LDR_RESULT {
	UINT32 maxEntropySources;
	BOOT_ENTROPY_SOURCE_LDR_RESULT EntropySourceResult[BootMaxEntropySources];
	UINT8 SeedBytesForCng[BOOT_SEED_BYTES_FOR_CNG];
	UINT8 RngBytesForNtoskrnl[BOOT_RNG_BYTES_FOR_NTOSKRNL];

	//
	// This field was added in an unknown Windows 10 revision after 10.0.10586.0
	//
	UINT8 KdEntropy[32];
} BOOT_ENTROPY_LDR_RESULT, *PBOOT_ENTROPY_LDR_RESULT;

//
// Hypervisor specific loader parameters.
//
typedef struct _LOADER_PARAMETER_HYPERVISOR_EXTENSION {

	//
	// Hypervisor crashdump pages if present.
	//
	UINT32 InitialHypervisorCrashdumpAreaPageCount;
	UINT32 HypervisorCrashdumpAreaPageCount;
	UINT64 InitialHypervisorCrashdumpAreaSpa;
	UINT64 HypervisorCrashdumpAreaSpa;

	//
	// Hypervisor launch status.
	//
	UINT64 HypervisorLaunchStatus;
	UINT64 HypervisorLaunchStatusArg1;
	UINT64 HypervisorLaunchStatusArg2;
	UINT64 HypervisorLaunchStatusArg3;
	UINT64 HypervisorLaunchStatusArg4;

} LOADER_PARAMETER_HYPERVISOR_EXTENSION, *PLOADER_PARAMETER_HYPERVISOR_EXTENSION;

//
// Code Integrity specific loader parameters.
//
typedef struct _LOADER_PARAMETER_CI_EXTENSION
{
	UINT32 CodeIntegrityOptions;
	struct {
		UINT32 UpgradeInProgress : 1;
		UINT32 IsWinPE : 1;
		UINT32 CustomKernelSignersAllowed : 1;
		UINT32 Reserved : 29;
	} s;
	LARGE_INTEGER WhqlEnforcementDate;
	UINT32 RevocationListOffset;
	UINT32 RevocationListSize;
	UINT32 CodeIntegrityPolicyOffset;
	UINT32 CodeIntegrityPolicySize;
	UINT32 CodeIntegrityPolicyHashOffset;
	UINT32 CodeIntegrityPolicyHashSize;
	UINT32 CodeIntegrityPolicyOriginalHashOffset;
	UINT32 CodeIntegrityPolicyOriginalHashSize;
	INT32 WeakCryptoPolicyLoadStatus;
	UINT32 WeakCryptoPolicyOffset;
	UINT32 WeakCryptoPolicySize;
	UINT32 SecureBootPolicyOffset;
	UINT32 SecureBootPolicySize;
	UINT32 Reserved2;
	UINT8 SerializedData[ANYSIZE_ARRAY]; // RevocationListSize bytes
} LOADER_PARAMETER_CI_EXTENSION, *PLOADER_PARAMETER_CI_EXTENSION;

typedef struct _HAL_EXTENSION_INSTANCE_ENTRY {

	//
	// Link into HalExtensionInstanceList in HAL_EXTENSION_MODULE_ENTRY.
	//
	LIST_ENTRY ListEntry;

	//
	// Offset from the start of the ACPI Core System Resource Table to
	// the Resource Group associate with this instance.
	//
	UINT32 OffsetIntoCsrt;
} HAL_EXTENSION_INSTANCE_ENTRY, *PHAL_EXTENSION_INSTANCE_ENTRY;

typedef struct _HAL_EXTENSION_MODULE_ENTRY {

	//
	// Link into HalExtensionList in LOADER_PARAMETER_EXTENSION.
	//
	LIST_ENTRY ListEntry;

	//
	// Pointer to the associated module entry on the LoadOrderListHead list.
	// This keeps info on the module name and entry point, among other things.
	//
	VOID* HalExtensionInfo;

	//
	// List of HAL_EXTENSION_INSTANCE_ENTRY structures tracking which Resource
	// Groups this extension is installed on.
	//
	LIST_ENTRY HalExtensionInstanceList;

	//
	// Name and load status of the HAL Extension for debugging purposes.
	//
	NTSTATUS ModuleLoadStatus;
	CHAR8* ModuleName;
	CHAR8* ModulePath;

} HAL_EXTENSION_MODULE_ENTRY, *PHAL_EXTENSION_MODULE_ENTRY;

typedef struct _LOADER_BUGCHECK_PARAMETERS {

	//
	// Bugcheck parameters passed to the kernel.
	//
	UINT32 BugcheckCode;
	UINTN BugcheckParameter1;
	UINTN BugcheckParameter2;
	UINTN BugcheckParameter3;
	UINTN BugcheckParameter4;
} LOADER_BUGCHECK_PARAMETERS, *PLOADER_BUGCHECK_PARAMETERS;

//
// Since 10.0.14393.0
//
typedef struct _LEAP_SECOND_DATA {
	UINT8 Enabled;
	UINT32 Count;
	LARGE_INTEGER Data[1];
} LEAP_SECOND_DATA, *PLEAP_SECOND_DATA;

//
// Since 10.0.15063.0
//
typedef struct _LOADER_RESET_REASON {
	UINT8 Supplied;
	union {
		struct {
			UINT64 Pch : 1;
			UINT64 EmbeddedController : 1;
			UINT64 Reserved : 6;
		} Component;
		UINT64 AsULONG64;
		UINT8 AsBytes[8];
	} Basic;
	UINT32 AdditionalInfo[8];
} LOADER_RESET_REASON, *PLOADER_RESET_REASON;

//
// Since 10.0.18362.0
//
typedef struct _VSM_PERFORMANCE_DATA {
	UINT64 LaunchVsmMark[8];
} VSM_PERFORMANCE_DATA, *PVSM_PERFORMANCE_DATA;

typedef struct _LOADER_HIVE_RECOVERY_INFO {
	struct {
		//
		// 1 if the hive was recovered by the boot loader, 0 otherwise.
		//
		UINT32 Recovered : 1;

		//
		// 1 if recovery from a legacy log file was performed, 0 otherwise.
		//
		UINT32 LegacyRecovery : 1;

		//
		// 1 if this hive was loaded as part of a soft reboot and encountered
		// a sharing violation during the load (causing it to be loaded from
		// a copy). 0 otherwise.
		//
		UINT32 SoftRebootConflict : 1;

		//
		// The most recent log from which recovery was performed as an 
		// HFILE_TYPE.
		//
		// i.e. For legacy recovery the individual log file recovery was
		// performed from, otherwise the log from which the highest
		// sequence numbered entry was from.
		//
		UINT32 MostRecentLog : 3;
		
		UINT32 Spare		: ((sizeof(UINT32) * 8) - 5);
	} s;

	//
	// The sequence number that should be used for the next log entry.
	//
	UINT32 LogNextSequence;

	//
	// The minimum sequence number in the most recent log.
	//
	UINT32 LogMinimumSequence;

	//
	// The file offset at which the next log entry should be written in the
	// most recent log.
	//
	UINT32 LogCurrentOffset;
} LOADER_HIVE_RECOVERY_INFO, *PLOADER_HIVE_RECOVERY_INFO;

//
// Internal boot flags definitions.
//
#define INTERNAL_BOOT_FLAGS_NONE				0x00000000
#define INTERNAL_BOOT_FLAGS_UTC_BOOT_TIME		0x00000001
#define INTERNAL_BOOT_FLAGS_RTC_BOOT_TIME		0x00000002
#define INTERNAL_BOOT_FLAGS_NO_LEGACY_SERVICES	0x00000004

typedef struct _LOADER_PARAMETER_EXTENSION {
	UINT32 Size; // set to sizeof (struct _LOADER_PARAMETER_EXTENSION)
	PROFILE_PARAMETER_BLOCK Profile;

	//
	// Errata Manager inf file.
	//
	VOID* EmInfFileImage;
	UINT32 EmInfFileSize;

	//
	// Pointer to the triage block, if present.
	//
	VOID* TriageDumpBlock;

	struct _HEADLESS_LOADER_BLOCK *HeadlessLoaderBlock;

	struct _SMBIOS3_TABLE_HEADER *SMBiosEPSHeader;

	VOID* DrvDBImage; // Database used to identify "broken" drivers.
	UINT32 DrvDBSize;

	// If booting from the Network (PXE) then we will
	// save the Network boot params in this loader block
	struct _NETWORK_LOADER_BLOCK *NetworkLoaderBlock;

#if defined(_X86_)
	//
	// Pointers to IRQL translation tables that reside in the HAL
	// and are exposed to the kernel for use in the "inlined IRQL"
	// build
	//
	UINT8* HalpIRQLToTPR;
	UINT8* HalpVectorToIRQL;
#endif

	//
	// Firmware Location
	//
	LIST_ENTRY FirmwareDescriptorListHead;

	//
	// Pointer to the in-memory copy of override ACPI tables. The override
	// table file is a simple binary file with one or more ACPI tables laid
	// out one after another.
	//
	VOID* AcpiTable;

	//
	// Size of override ACPI tables in bytes.
	//
	UINT32 AcpiTableSize;

	//
	// Various informational flags passed to OS via OS Loader.
	//
	struct {
		//
		// Variables describing the success of the previous boot - whether
		// booting into the OS was successful, and whether the arc from boot to
		// runtime to shutdown was successful. Various types of system crashes
		// will cause one or both of these to be FALSE.
		//
		UINT32 LastBootSucceeded : 1;
		UINT32 LastBootShutdown : 1;

		//
		// A flag indicating whether the platform supports access to IO ports.
		//
		UINT32 IoPortAccessSupported : 1;

		//
		// A flag indicating whether or not the boot debugger persisted
		// through kernel initialization.
		//
		UINT32 BootDebuggerActive : 1;

		//
		// A flag indicating whether the system must enforce strong code
		// guarantees.
		//
		UINT32 StrongCodeGuarantees : 1;

		//
		// A flag indicating whether the system must enforce hard strong code
		// guarantees.
		//
		UINT32 HardStrongCodeGuarantees : 1;

		//
		// A flag indicating whether SID sharing disabled.
		//
		UINT32 SidSharingDisabled : 1;

		//
		// A flag indicating whether TPM was intialized successfully or not
		// by the OS loader during boot.
		//
		UINT32 TpmInitialized : 1;

		//
		// A flag indicating whether the VSM code page has been configured and
		// is usable.
		//
		UINT32 VsmConfigured : 1;

		//
		// A flag indicating whether IUM is enabled.
		//
		UINT32 IumEnabled : 1;

		//
		// A flag indicating whether we're booting from SMB
		//
		UINT32 IsSmbboot : 1;

		//
		// Below added in 10.0.14393.0
		//
		UINT32 BootLogEnabled : 1;

		//
		// Below added in 10.0.17134.0
		//
		UINT32 DriverVerifierEnabled : 1;

		UINT32 Unused : 8;

		UINT32 FeatureSimulations : 6;

		UINT32 MicrocodeSelfHosting : 1;

		UINT32 XhciLegacyHandoffSkip : 1;

		//
		// Below added in 10.0.17763.0
		//
		UINT32 DisableInsiderOptInHVCI : 1;

		UINT32 MicrocodeMinVerSupported : 1;

		UINT32 GpuIommuEnabled : 1;
	} s;

	//
	// Loader runtime performance data.
	//
	// This was a pointer to LOADER_PERFORMANCE_DATA until 10.0.17763.0
	//
	LOADER_PERFORMANCE_DATA LoaderPerformanceData;

	//
	// Boot application persistent data.
	//
	LIST_ENTRY BootApplicationPersistentData;

	//
	// Windows Memory Diagnostic Test Results.
	//
	VOID* WmdTestResult;

	//
	// Boot entry identifier.
	//
	GUID BootIdentifier;

	//
	// The number of pages to reserve for the resume application to use as
	// scratch space. This should correspond to the boot environment's memory
	// footprint.
	//
	UINT32 ResumePages;

	//
	// The crash dump header, if present.
	//
	VOID* DumpHeader;

	//
	// Boot graphics context.
	//
	VOID* BgContext;

	//
	// NUMA node locality information and group assignment data.
	//
	VOID* NumaLocalityInfo;
	VOID* NumaGroupAssignment;

	//
	// List of hives attached by loader
	//
	LIST_ENTRY AttachedHives;

	//
	// Number of entries in the MemoryCachingRequirements map.
	//
	UINT32 MemoryCachingRequirementsCount;

	//
	// List of MEMORY_CACHING_REQUIREMENTS for the system.
	//
	VOID* MemoryCachingRequirements;

	//
	// Result of the Boot entropy gathering.
	//
	BOOT_ENTROPY_LDR_RESULT BootEntropyResult;

	//
	// Computed ITC/TSC frequency of the BSP in hertz.
	//
	UINT64 ProcessorCounterFrequency;

	//
	// Hypervisor specific information.
	//
	LOADER_PARAMETER_HYPERVISOR_EXTENSION HypervisorExtension;

	//
	// Hardware configuration ID used to uniquelly identify the system.
	//
	GUID HardwareConfigurationId;

	//
	// List of HAL_EXTENSION_MODULE_ENTRY structures.
	//
	LIST_ENTRY HalExtensionModuleList;

	//
	// Contains most recent time from firmware, bootstat.dat and ntos build time.
	//
	LARGE_INTEGER SystemTime;

	//
	// Contains cycle counter timestamp at the time SystemTime value was read.
	//
	UINT64 TimeStampAtSystemTimeRead;

	//
	// Boot Flags that are passed to the SystemBootEnvironmentInformation class.
	//
	union {
		UINT64 BootFlags;
		struct {
			UINT64 DbgMenuOsSelection : 1;
			UINT64 DbgHiberBoot : 1;
			UINT64 DbgSoftRestart : 1;
			UINT64 DbgMeasuredLaunch : 1;
		} s;
	} u1;

	//
	// Internal only flags that are passed to the kernel.
	//
	union {
		UINT64 InternalBootFlags;
		struct {
			UINT64 DbgUtcBootTime : 1;
			UINT64 DbgRtcBootTime : 1;
			UINT64 DbgNoLegacyServices : 1;
		} s;
	} u2;

	//
	// Pointer to the in-memory copy of the Wfs FP data.
	//
	VOID* WfsFPData;

	//
	// Size of Wfs FP data in bytes.
	//
	UINT32 WfsFPDataSize;

	//
	// Loader bugcheck parameters for the kernel or extensions to act upon
	//
	LOADER_BUGCHECK_PARAMETERS BugcheckParameters;

	//
	// API set schema data.
	//
	VOID* ApiSetSchema;
	UINT32 ApiSetSchemaSize;
	LIST_ENTRY ApiSetSchemaExtensions;

	//
	// The system's firmware version according to ACPI's FADT,
	// SMBIOS's BIOS information table, and EFI's system table respectively.
	//
	UNICODE_STRING AcpiBiosVersion;
	UNICODE_STRING SmbiosVersion;
	UNICODE_STRING EfiVersion;

	//
	// Debugger Descriptor
	//
	struct _DEBUG_DEVICE_DESCRIPTOR *KdDebugDevice;

	//
	// EFI Offline crashdump configuration table.
	//
	OFFLINE_CRASHDUMP_CONFIGURATION_TABLE OfflineCrashdumpConfigurationTable;

	//
	// Manufacturing mode profile name.
	//
	UNICODE_STRING ManufacturingProfile;

	//
	// BBT Buffer to enable precise event based sampling.
	//
	VOID* BbtBuffer;

	//
	// Registry values to be passed to the kernel for calculation of Xsave Buffer Size on Intel platforms
	//
#if defined(_X86_) || defined (_AMD64_)
	UINT64 XsaveAllowedFeatures;
	UINT32 XsaveFlags;
#endif

	//
	// Boot options used by the OS loader.
	//
	VOID* BootOptions;

	//
	// These fields were added and/or moved forward in 10.0.17763.0
	//
	UINT32 IumEnablement;
	UINT32 IumPolicy;
	INT32 IumStatus;

	//
	// Boot sequence tracking for reliability reporting.
	//
	UINT32 BootId;

	//
	// Code Integrity configuration.
	//
	PLOADER_PARAMETER_CI_EXTENSION CodeIntegrityData;
	UINT32 CodeIntegrityDataSize;

	LOADER_HIVE_RECOVERY_INFO SystemHiveRecoveryInfo;

	//
	// Below fields added in 10.0.14393.0
	//
	UINT32 SoftRestartCount;

	INT64 SoftRestartTime;

	VOID* HypercallCodeVa;

	VOID* HalVirtualAddress;

	UINT64 HalNumberOfBytes;

	PLEAP_SECOND_DATA LeapSecondData;

	UINT32 MajorRelease;

	UINT32 Reserved1;

	//
	// Below fields added in 10.0.15063.0
	//
	CHAR8 NtBuildLab[224];

	CHAR8 NtBuildLabEx[224];

	LOADER_RESET_REASON ResetReason;

	//
	// Below field added in 10.0.17134.0
	//
	UINT32 MaxPciBusNumber;

	//
	// Below field added in 10.0.17763.0
	//
	UINT32 FeatureSettings;

	//
	// Below fields added in 10.0.18362.0
	//
	UINT32 HotPatchReserveSize;

	UINT32 RetpolineReserveSize;

	struct
	{
		VOID* CodeBase;
		UINTN CodeSize;
	} MiniExecutive;

	VSM_PERFORMANCE_DATA VsmPerformanceData;
} LOADER_PARAMETER_EXTENSION, *PLOADER_PARAMETER_EXTENSION;

struct _HEADLESS_LOADER_BLOCK;
struct _SMBIOS_TABLE_HEADER;

typedef struct _NETWORK_LOADER_BLOCK {

	// Binary contents of the entire DHCP Acknowledgment
	// packet received by PXE.
	UINT8* DHCPServerACK;
	UINT32 DHCPServerACKLength;

	// Binary contents of the entire BINL Reply
	// packet received by PXE.
	UINT8* BootServerReplyPacket;
	UINT32 BootServerReplyPacketLength;

} NETWORK_LOADER_BLOCK, *PNETWORK_LOADER_BLOCK;

typedef struct _VIRTUAL_EFI_RUNTIME_SERVICES {

	//
	// (Virtual) Entry points to each of the EFI Runtime services.
	//
	UINTN GetTime;
	UINTN SetTime;
	UINTN GetWakeupTime;
	UINTN SetWakeupTime;
	UINTN SetVirtualAddressMap;
	UINTN ConvertPointer;
	UINTN GetVariable;
	UINTN GetNextVariableName;
	UINTN SetVariable;
	UINTN GetNextHighMonotonicCount;
	UINTN ResetSystem;
	UINTN UpdateCapsule;
	UINTN QueryCapsuleCapabilities;
	UINTN QueryVariableInfo;

} VIRTUAL_EFI_RUNTIME_SERVICES, *PVIRTUAL_EFI_RUNTIME_SERVICES;

typedef struct _EFI_FIRMWARE_INFORMATION {
	UINT32 FirmwareVersion;
	PVIRTUAL_EFI_RUNTIME_SERVICES VirtualEfiRuntimeServices;

	//
	// The return value from SetVirtualAddressMap call.
	//
	NTSTATUS SetVirtualAddressMapStatus;

	//
	// Number of mappings missed if any due to change in firmware
	// runtime memory map (for debugging).
	//
	UINT32 MissedMappingsCount;

	//
	// The firmware resource list identifies firmware components that can
	// be updated via WU.
	//
	LIST_ENTRY FirmwareResourceList;

	//
	// The EFI memory map.
	//
	VOID* EfiMemoryMap;
	UINT32 EfiMemoryMapSize;
	UINT32 EfiMemoryMapDescriptorSize;

} EFI_FIRMWARE_INFORMATION, *PEFI_FIRMWARE_INFORMATION;

typedef struct _PCAT_FIRMWARE_INFORMATION {
	UINT32 PlaceHolder;
} PCAT_FIRMWARE_INFORMATION, *PPCAT_FIRMWARE_INFORMATION;

typedef struct _FIRMWARE_INFORMATION_LOADER_BLOCK {
	struct {
		//
		// If set to TRUE, indicates that the system is running on EFI
		// firmware.
		//
		UINT32 FirmwareTypeEfi: 1;

		//
		// A flag indicating whether EFI runtime service calls must be routed
		// through IUM.
		//
		UINT32 EfiRuntimeUseIum: 1;

		//
		// A flag indicating whether EFI runtime code and data pages are
		// separate and protected with RW or RX protections.
		//
		//UINT32 EfiRuntimePageProtectionEnabled: 1; // This was removed again in 10.0.14393.0

		//
		// A flag indicating whether the firmware supports code and data page
		// separation with restricted protections.
		//
		UINT32 EfiRuntimePageProtectionSupported: 1;

#if defined (_ARM64_)
		//
		// If set to TRUE, indicates that the system EFI was started in EL2
		// and therefore has something running there (hypervisor/microvisor).
		// Also, this is where APs will start (EL2), and need to be directed
		// to EL1 properly before they can start in the HLOS.
		//
		UINT32 FirmwareStartedInEL2: 1;
		UINT32 Reserved: 28;
#else
		UINT32 Reserved: 29;
#endif
	} s;

	union {
		EFI_FIRMWARE_INFORMATION EfiInformation;
		PCAT_FIRMWARE_INFORMATION PcatInformation;
	} u;

} FIRMWARE_INFORMATION_LOADER_BLOCK, *PFIRMWARE_INFORMATION_LOADER_BLOCK;

//
// I'd just like to interject for a moment... without this the next struct won't compile.
// Source: kernel PDBs once in a blue moon
//
typedef struct _KLDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	VOID* ExceptionTable;
	UINT32 ExceptionTableSize;
	VOID* GpValue;
	struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
	VOID* DllBase;
	VOID* EntryPoint;
	UINT32 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	UINT32 Flags;
	UINT16 LoadCount;
	union {
		struct {
			UINT16 SignatureLevel : 4;
			UINT16 SignatureType : 3;
			UINT16 Unused : 9;
		} s;
		UINT16 EntireField;
	} u;
	VOID* SectionPointer;
	UINT32 CheckSum;
	UINT32 CoverageSectionSize;
	VOID* CoverageSection;
	VOID* LoadedImports;
	VOID* Spare;

	// Below fields are Win 10+ only
	UINT32 SizeOfImageNotRounded;
	UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

//
// Boot loader data table entry. Each of the load lists in the parameter block
// consist of boot loader data table entries.
//
// N.B. This structure requires ntldr.h to have been included.
//
#define BLDR_FLAGS_CORE_DRIVER_DEPENDENT_DLL		0x00000001
#define BLDR_FLAGS_CORE_EXTENSION_DEPENDENT_DLL		0x00000002

typedef struct _BLDR_DATA_TABLE_ENTRY {
	KLDR_DATA_TABLE_ENTRY KldrEntry;
	UNICODE_STRING CertificatePublisher;
	UNICODE_STRING CertificateIssuer;
	VOID* ImageHash;
	VOID* CertificateThumbprint;
	UINT32 ImageHashAlgorithm;
	UINT32 ThumbprintHashAlgorithm;
	UINT32 ImageHashLength;
	UINT32 CertificateThumbprintLength;
	UINT32 LoadInformation;
	UINT32 Flags;
} BLDR_DATA_TABLE_ENTRY, *PBLDR_DATA_TABLE_ENTRY;

#define OSLOADER_SECURITY_VERSION_CURRENT 1

typedef struct _LOADER_PARAMETER_BLOCK {
	UINT32 OsMajorVersion;
	UINT32 OsMinorVersion;
	UINT32 Size;
	UINT32 OsLoaderSecurityVersion;
	LIST_ENTRY LoadOrderListHead;
	LIST_ENTRY MemoryDescriptorListHead;

	//
	// Define the Core, TPM Core and Core Extensions driver lists. The
	// lists are organized as follows:
	//
	// 1. Core Drivers: This list consists of drivers that ELAM drivers and
	//		3rd party Core Extensions depend upon (e.g. WDF, CNG.sys). All
	//		drivers in this group should be MS-supplied and thus MS-signed.
	//
	// 2. ELAM drivers. This list consists of 3rd party ELAM drivers. These
	//		drivers need to be signed with ELAM certificate.
	//
	// 3. Core Extensions: This list consists of 3rd party drivers (viz.
	//		Platform Extensions and Tree drivers) that TPM Core drivers
	//		depend upon. These drivers need to be signed with Core Extension
	//		certificate.
	//
	// 4. TPM Core: This list consists of TPM driver and bus drivers (e.g.
	//		ACPI, PCI) that are necessary to enumerate TPM. All drivers in
	//		this group should be MS-supplied and thus MS-signed.
	//
	// 5. Boot Driver: This list contains the rest of the boot drivers.
	//
	LIST_ENTRY BootDriverListHead;
	LIST_ENTRY EarlyLaunchListHead;
	LIST_ENTRY CoreDriverListHead;
	LIST_ENTRY CoreExtensionsDriverListHead;
	LIST_ENTRY TpmCoreDriverListHead;
	UINTN KernelStack;
	UINTN Prcb;
	UINTN Process;
	UINTN Thread;
	UINT32 KernelStackSize;
	UINT32 RegistryLength;
	VOID* RegistryBase;
	PCONFIGURATION_COMPONENT_DATA ConfigurationRoot;
	CHAR8* ArcBootDeviceName;
	CHAR8* ArcHalDeviceName;
	CHAR8* NtBootPathName;
	CHAR8* NtHalPathName;
	CHAR8* LoadOptions;
	PNLS_DATA_BLOCK NlsData;
	PARC_DISK_INFORMATION ArcDiskInformation;
	PLOADER_PARAMETER_EXTENSION Extension;
	union {
		I386_LOADER_BLOCK I386;
		ARM_LOADER_BLOCK Arm;
	} u;
	FIRMWARE_INFORMATION_LOADER_BLOCK FirmwareInformation;

	//
	// Below added in 10.0.17134.0
	//
	CHAR8* OsBootstatPathName;
	CHAR8* ArcOSDataDeviceName;
	CHAR8* ArcWindowsSysPartName;
} LOADER_PARAMETER_BLOCK, *PLOADER_PARAMETER_BLOCK;


#define LHB_SYSTEM_HIVE			0x01
#define LHB_BOOT_PARTITION		0x02
#define LHB_SYSTEM_PARTITION	0x04
#define LHB_ELAM_HIVE			0x08
#define LHB_MOUNT_VOLATILE		0x10

#define LHB_VALID_FLAGS	(LHB_SYSTEM_HIVE | LHB_BOOT_PARTITION | LHB_SYSTEM_PARTITION | LHB_ELAM_HIVE | LHB_MOUNT_VOLATILE)

typedef struct _LOADER_HIVE_BLOCK {
	LIST_ENTRY Entry;
	CHAR16* FilePath;
	UINT32 Flags;
	VOID* RegistryBase;
	UINT32 RegistryLength;
	CHAR16* RegistryName;
	CHAR16* RegistryParent;
	LOADER_HIVE_RECOVERY_INFO RecoveryInfo;
} LOADER_HIVE_BLOCK, *PLOADER_HIVE_BLOCK;

//
// Source: ReactOS bl.h
//
typedef struct _BL_RETURN_ARGUMENTS {
	UINT32 Version;
	UINT32 Status;
	UINT32 Flags;
	UINT64 DataSize;
	UINT64 DataPage;
} BL_RETURN_ARGUMENTS, *PBL_RETURN_ARGUMENTS;

typedef struct _BL_BCD_OPTION {
	UINT32 Type;
	UINT32 DataOffset;
	UINT32 DataSize;
	UINT32 ListOffset;
	UINT32 NextEntryOffset;
	UINT32 Empty;
} BL_BCD_OPTION, *PBL_BCD_OPTION;

typedef struct _BL_APPLICATION_ENTRY {
	CHAR8 Signature[8];
	UINT32 Flags;
	EFI_GUID Guid;
	UINT32 Unknown[4];
	BL_BCD_OPTION BcdData;
} BL_APPLICATION_ENTRY, *PBL_APPLICATION_ENTRY;

typedef struct _BL_LOADED_APPLICATION_ENTRY {
	UINT32 Flags;
	EFI_GUID Guid;
	PBL_BCD_OPTION BcdData;
} BL_LOADED_APPLICATION_ENTRY, *PBL_LOADED_APPLICATION_ENTRY;
