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
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  CpuLib|MdePkg/Library/BaseCpuLib/BaseCpuLib.inf
  PciCf8Lib|MdePkg/Library/BasePciCf8Lib/BasePciCf8Lib.inf
  PciLib|MdePkg/Library/BasePciLibCf8/BasePciLibCf8.inf
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsicSev.inf
  SerialPortLib|PcAtChipsetPkg/Library/SerialIoLib/SerialIoLib.inf

  # UEFI and PI
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf

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

  # Note [2021-05-27]: the current EDK2 master branch, and releases starting from edk2-stable202105, require an instance of the new 'RegisterFilterLib' in order to use BaseLib, even if you do not use RegisterFilterLib:
  # https://github.com/tianocore/edk2/commit/1c11e7a2142b1406ccff5e0af0893c94472871c8
  # Since there is no macro available to determine the version of EDK2, the build *has* to be broken for either master/latest *or* any even slightly-older-than-latest releases because of this trivial issue.
  # The following line therefore fixes builds when compiling with recent EDK2 versions, but breaks builds when compiling with EDK2 versions older than edk2-stable202105.
  #
  # TLDR: if you receive an error along the lines of 'RegisterFilterLibNull.inf not found in packages path', you can simply comment out the following line, since it does nothing useful:
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf

[LibraryClasses.common.DXE_DRIVER, LibraryClasses.common.DXE_RUNTIME_DRIVER, LibraryClasses.common.DXE_SMM_DRIVER, LibraryClasses.common.UEFI_DRIVER]
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibOptDxe/BaseMemoryLibOptDxe.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/RuntimeDxeReportStatusCodeLib/RuntimeDxeReportStatusCodeLib.inf

[LibraryClasses.common.UEFI_APPLICATION]
  PcdLib|MdePkg/Library/DxePcdLib/DxePcdLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibOptDxe/BaseMemoryLibOptDxe.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  ReportStatusCodeLib|MdeModulePkg/Library/DxeReportStatusCodeLib/DxeReportStatusCodeLib.inf

  # Stuff needed for UefiBootManagerLib
  PerformanceLib|MdePkg/Library/BasePerformanceLibNull/BasePerformanceLibNull.inf
  UefiHiiServicesLib|MdeModulePkg/Library/UefiHiiServicesLib/UefiHiiServicesLib.inf
  HiiLib|MdeModulePkg/Library/UefiHiiLib/UefiHiiLib.inf
  SortLib|MdeModulePkg/Library/UefiSortLib/UefiSortLib.inf
  DxeServicesLib|MdePkg/Library/DxeServicesLib/DxeServicesLib.inf
  DxeServicesTableLib|MdePkg/Library/DxeServicesTableLib/DxeServicesTableLib.inf
  PeCoffGetEntryPointLib|MdePkg/Library/BasePeCoffGetEntryPointLib/BasePeCoffGetEntryPointLib.inf
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf
  UefiBootManagerLib|MdeModulePkg/Library/UefiBootManagerLib/UefiBootManagerLib.inf

[Components]
  # DXE driver
  EfiGuardPkg/EfiGuardDxe/EfiGuardDxe.inf

  # Loader application
  EfiGuardPkg/Application/Loader/Loader.inf

[BuildOptions.Common]
  *_*_*_CC_FLAGS = -D DISABLE_NEW_DEPRECATED_INTERFACES
!if $(CONFIGURE_DRIVER) == 1
  *_*_*_CC_FLAGS = -D CONFIGURE_DRIVER=1
!endif

  # Source files are UTF-8 without BOM. MSVC will convert other encodings to this without asking, so this is not really a choice
  MSFT:*_*_*_CC_FLAGS = /utf-8
  INTEL:*_*_*_CC_FLAGS = /utf-8
  GCC:*_*_*_CC_FLAGS = -finput-charset=UTF-8

  # ICC generates about a million of these for Zydis on /W4, and then quits because of /WX.
  # warning #188: enumerated type mixed with another type
  # message #2415: variable "x" of static storage duration was declared but never referenced
  INTEL:*_*_*_CC_FLAGS = /wd188,2415

  # Pre-emptive strike for when this horrible option inevitably becomes the default
  MSFT:*_*_*_CC_FLAGS = /Qspectre-

  # Use sane linker flags instead of EDK2 defaults
  MSFT:*_*_*_DLINK_FLAGS = /ALIGN:0x1000 /FILEALIGN:0x200 /SECTION:.pdata,!D /MERGE:.rdata=.text /DEBUG:FULL /NOVCFEATURE /NOCOFFGRPINFO /PDBALTPATH:%_PDB%
  INTEL:*_*_*_DLINK_FLAGS = /ALIGN:0x1000 /FILEALIGN:0x200 /SECTION:.pdata,!D /MERGE:.rdata=.text /DEBUG:FULL /NOVCFEATURE /NOCOFFGRPINFO /PDBALTPATH:%_PDB%
  GCC:*_GCC5_*_DLINK_FLAGS = -z common-page-size=0x1000
  GCC:*_CLANGPDB_*_DLINK_FLAGS = /ALIGN:0x1000 /FILEALIGN:0x200 /DRIVER
  MSFT:*_*_X64_GENFW_FLAGS = --keepexceptiontable --keepzeropending --keepoptionalheader
