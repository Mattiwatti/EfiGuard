[Defines]
  PLATFORM_NAME                  = EfiGuard
  PLATFORM_GUID                  = C5ACE17D-FD90-44F7-847C-693ED2B8BEF9
  PLATFORM_VERSION               = 1.00
  DSC_SPECIFICATION              = 0x0001001B
  OUTPUT_DIRECTORY               = Build/EfiGuard
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE|NOOPT
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  # Entry points
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiApplicationEntryPoint|MdePkg/Library/UefiApplicationEntryPoint/UefiApplicationEntryPoint.inf

  # Basics
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  PciCf8Lib|MdePkg/Library/BasePciCf8Lib/BasePciCf8Lib.inf
  PciLib|MdePkg/Library/BasePciLibCf8/BasePciLibCf8.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  SerialPortLib|PcAtChipsetPkg/Library/SerialIoLib/SerialIoLib.inf

  # UEFI and PI
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf

  # Misc modules
  DevicePathLib|MdePkg/Library/UefiDevicePathLibDevicePathProtocol/UefiDevicePathLibDevicePathProtocol.inf
  FileHandleLib|MdePkg/Library/UefiFileHandleLib/UefiFileHandleLib.inf
  ShellLib|ShellPkg/Library/UefiShellLib/UefiShellLib.inf
!if $(TARGET) == RELEASE
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
!else
  !ifdef $(DEBUG_ON_SERIAL_PORT)
    DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
  !else
    DebugLib|MdePkg/Library/UefiDebugLibConOut/UefiDebugLibConOut.inf
  !endif
!endif
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf

[LibraryClasses.IA32, LibraryClasses.X64]
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibOptDxe/BaseMemoryLibOptDxe.inf

[LibraryClasses.common.UEFI_APPLICATION]
  # Stuff needed for UefiBootManagerLib
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  HiiLib|MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  DxeServicesLib|MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
  DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  VariablePolicyHelperLib|MdeModulePkg/Library/VariablePolicyHelperLib/VariablePolicyHelperLib.inf
  UefiBootManagerLib|MdeModulePkg/Library/UefiBootManagerLib/UefiBootManagerLib.inf

[PcdsFixedAtBuild]
!if $(TARGET) == DEBUG
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x07
!endif

  # Enable error and progress status code reporting
  gEfiMdePkgTokenSpaceGuid.PcdReportStatusCodePropertyMask|0x03

  # See https://edk2-devel.narkive.com/sSVnhXxV/edk2-bdssetmemorytypeinformationvariable
  gEfiMdeModulePkgTokenSpaceGuid.PcdResetOnMemoryTypeInformationChange|FALSE

[Components]
  # DXE driver
  EfiGuardPkg/EfiGuardDxe/EfiGuardDxe.inf

  # Loader application
  EfiGuardPkg/Application/Loader/Loader.inf

[BuildOptions.Common]
  *_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES

  # Source files are UTF-8 without BOM. MSVC will convert other encodings to this without asking, so this is not really a choice
  MSFT:*_*_*_CC_FLAGS = /utf-8
  INTEL:*_*_*_CC_FLAGS = /utf-8
  GCC:*_*_*_CC_FLAGS = -finput-charset=UTF-8

  # https://github.com/Mattiwatti/EfiGuard/issues/134
  # https://github.com/tianocore/edk2/issues/10547
  MSFT:*_*_*_CC_FLAGS = /GS-
  GCC:*_*_*_CC_FLAGS = -fno-stack-protector

  # Pre-emptive strike for when this horrible option inevitably becomes the default
  MSFT:*_*_*_CC_FLAGS = /Qspectre-

  # Use sane linker flags instead of EDK2 defaults
  MSFT:*_*_*_DLINK_FLAGS = /ALIGN:0x1000 /FILEALIGN:0x200 /SECTION:.pdata,!D /SECTION:.xdata,!D /DEBUG:FULL /NOVCFEATURE /NOCOFFGRPINFO /PDBALTPATH:%_PDB%
  INTEL:*_*_*_DLINK_FLAGS = /ALIGN:0x1000 /FILEALIGN:0x200 /SECTION:.pdata,!D /SECTION:.xdata,!D /DEBUG:FULL /NOVCFEATURE /NOCOFFGRPINFO /PDBALTPATH:%_PDB%
!if $(TOOL_CHAIN_TAG) != "XCODE5" && $(TOOL_CHAIN_TAG) != "CLANGPDB"
  GCC:*_*_*_DLINK_FLAGS = -z common-page-size=0x1000
!else if $(TOOL_CHAIN_TAG) == "CLANGPDB"
  GCC:*_*_*_DLINK_FLAGS = /ALIGN:0x1000 /FILEALIGN:0x200 /DRIVER
!endif

  # Tell GenFw not to drop the exception table or the optional header containing the checksum
  *:*_*_X64_GENFW_FLAGS = --keepexceptiontable --keepzeropending --keepoptionalheader
