#pragma once

#include "ntdll.h"

#if defined(__cplusplus) && \
	((defined(_MSC_VER) && (_MSC_VER >= 1900)) || defined(__clang__))
#define CONSTEXPR constexpr
#else
#define CONSTEXPR
#endif

#if defined(__RESHARPER__)
#define WPRINTF_ATTR(FormatIndex, FirstToCheck) \
	[[rscpp::format(wprintf, FormatIndex, FirstToCheck)]]
#else
#define WPRINTF_ATTR(FormatIndex, FirstToCheck)
#endif

#ifdef __cplusplus
extern "C" {
#endif

// EfiDSEFix.cpp
NTSTATUS
TestSetVariableHook(
	);

NTSTATUS
AdjustCiOptions(
	_In_ ULONG CiOptionsValue,
	_Out_opt_ PULONG OldCiOptionsValue
	);

// sysinfo.cpp
NTSTATUS
DumpSystemInformation(
	);

// pe.cpp
NTSTATUS
MapFileSectionView(
	_In_ PCWCHAR Filename,
	_Out_ PVOID *ImageBase,
	_Out_ PSIZE_T ViewSize
	);

BOOLEAN
AddressIsInSection(
	_In_ PUCHAR ImageBase,
	_In_ PUCHAR Address,
	_In_ PIMAGE_NT_HEADERS NtHeaders,
	_In_ PCCH SectionName
	);

PVOID
GetProcedureAddress(
	_In_ ULONG_PTR DllBase,
	_In_ PCCH RoutineName
	);

FORCEINLINE
ULONG
RtlNtMajorVersion(
	)
{
	return *(PULONG)(0x7FFE0000 + 0x026C);
}

FORCEINLINE
ULONG
RtlNtMinorVersion(
	)
{
	return *(PULONG)(0x7FFE0000 + 0x0270);
}

CONSTEXPR
FORCEINLINE
LONGLONG
RtlMsToTicks(
	_In_ ULONG Milliseconds
	)
{
	return 10000LL * (LONGLONG)Milliseconds;
}

FORCEINLINE
VOID
RtlSleep(
	_In_ ULONG Milliseconds
	)
{
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -1 * RtlMsToTicks(Milliseconds);
	NtDelayExecution(FALSE, &Timeout);
}

// Ntdll string functions, not in ntdll.h as they are incompatible with the CRT
typedef const WCHAR *LPCWCHAR, *PCWCHAR;

NTSYSAPI
int
__cdecl
_snwprintf(
	_Out_ PWCHAR Buffer,
	_In_ size_t BufferCount,
	_In_ PCWCHAR Format,
	...
	);

NTSYSAPI
int
__cdecl
_vsnwprintf(
	_Out_ PWCHAR Buffer,
	_In_ size_t BufferCount,
	_In_ PCWCHAR Format,
	_In_ va_list ArgList
	);

NTSYSAPI
ULONG
__cdecl
wcstoul(
	_In_ PCWCHAR String,
	_Out_opt_ PWCHAR* EndPtr,
	_In_ LONG Radix
	);

// Console functions
WPRINTF_ATTR(1, 2)
inline
VOID
Printf(
	_In_ PCWCHAR Format,
	...
	)
{
	WCHAR Buffer[512];
	va_list VaList;
	va_start(VaList, Format);
	ULONG N = _vsnwprintf(Buffer, sizeof(Buffer) / sizeof(WCHAR) - 1, Format, VaList);
	WriteConsoleW(NtCurrentPeb()->ProcessParameters->StandardOutput, Buffer, N, &N, NULL);
	va_end(VaList);
}

inline
VOID
PrintGuid(
	_In_ GUID Guid
	)
{
	Printf(L"{%08lx-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx}",
		Guid.Data1, Guid.Data2, Guid.Data3,
		Guid.Data4[0], Guid.Data4[1], Guid.Data4[2], Guid.Data4[3],
		Guid.Data4[4], Guid.Data4[5], Guid.Data4[6], Guid.Data4[7]);
}

inline
VOID
WaitForKey(
	)
{
	const HANDLE StdIn = NtCurrentPeb()->ProcessParameters->StandardInput;
	INPUT_RECORD InputRecord = { 0 };
	ULONG NumRead;
	while (InputRecord.EventType != KEY_EVENT || !InputRecord.Event.KeyEvent.bKeyDown || InputRecord.Event.KeyEvent.dwControlKeyState !=
		(InputRecord.Event.KeyEvent.dwControlKeyState & ~(RIGHT_CTRL_PRESSED | LEFT_CTRL_PRESSED)))
	{
		ReadConsoleInputW(StdIn, &InputRecord, 1, &NumRead);
	}
}

#ifdef NT_ANALYSIS_ASSUME
// wdm.h's asserts are incompatible with both clang and MS's own analyzer
#undef NT_ANALYSIS_ASSUME
#undef NT_ASSERT_ACTION
#undef NT_ASSERTMSG_ACTION
#undef NT_ASSERTMSGW_ACTION
#undef NT_ASSERT_ASSUME
#undef NT_ASSERTMSG_ASSUME
#undef NT_ASSERTMSGW_ASSUME
#undef NT_ASSERT
#undef NT_ASSERTMSG
#undef NT_ASSERTMSGW
#endif

#ifdef _PREFAST_
#define NT_ANALYSIS_ASSUME(...) _Analysis_assume_(__VA_ARGS__)
#elif defined(_DEBUG) || defined(DBG)
#define NT_ANALYSIS_ASSUME(...) ((void) 0)
#else
#define NT_ANALYSIS_ASSUME(...) __noop(__VA_ARGS__)
#endif

#if !defined(__clang__)
#if !defined(DbgRaiseAssertionFailure)
#define DbgRaiseAssertionFailure() __int2c()
#endif

#define NT_ASSERT_ACTION(_exp) \
	((!(_exp)) ? \
		(__annotation((PWCHAR)L"Debug", L"AssertFail", L#_exp), \
			DbgRaiseAssertionFailure(), FALSE) : \
		TRUE)

#define NT_ASSERTMSG_ACTION(_msg, _exp) \
	((!(_exp)) ? \
		(__annotation((PWCHAR)L"Debug", L"AssertFail", L##_msg), \
			DbgRaiseAssertionFailure(), FALSE) : \
		TRUE)

#define NT_ASSERTMSGW_ACTION(_msg, _exp) \
	((!(_exp)) ? \
		(__annotation((PWCHAR)L"Debug", L"AssertFail", _msg), \
			DbgRaiseAssertionFailure(), FALSE) : \
		TRUE)
#else
#define NT_ASSERT_ACTION(_exp) \
	((!(_exp)) ? (__debugbreak(), FALSE) : TRUE)
#define NT_ASSERTMSG_ACTION(_msg, _exp) \
	NT_ASSERT_ACTION(_exp)
#define NT_ASSERTMSGW_ACTION(_msg, _exp) \
	NT_ASSERT_ACTION(_exp)
#endif

#if defined(_DEBUG) || defined(DBG)
#define NT_ASSERT_ASSUME(_exp) \
	(NT_ANALYSIS_ASSUME(_exp), NT_ASSERT_ACTION(_exp))

#define NT_ASSERTMSG_ASSUME(_msg, _exp) \
	(NT_ANALYSIS_ASSUME(_exp), NT_ASSERTMSG_ACTION(_msg, _exp))

#define NT_ASSERTMSGW_ASSUME(_msg, _exp) \
	(NT_ANALYSIS_ASSUME(_exp), NT_ASSERTMSGW_ACTION(_msg, _exp))

#define NT_ASSERT					NT_ASSERT_ASSUME
#define NT_ASSERTMSG				NT_ASSERTMSG_ASSUME
#define NT_ASSERTMSGW				NT_ASSERTMSGW_ASSUME
#else
#define NT_ASSERT(_exp)				((void) 0)
#define NT_ASSERTMSG(_msg, _exp)	((void) 0)
#define NT_ASSERTMSGW(_msg, _exp)	((void) 0)
#endif

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#pragma warning(push)
#pragma warning(disable:4309)
// Convenience utility
// Usage: static_print<some_constant>()() gives the value as compiler warning C4305 or -Wconstant-conversion
template<ULONG N>
struct static_print
{
	CONSTEXPR CHAR operator()() const { return N + 256; }
};
#pragma warning(pop)

#define PRINT_SIZE(T) { static_print<sizeof(T)>()(); }
#define PRINT_OFFSET(T, V) { static_print<UFIELD_OFFSET(T, V)>()(); }

#endif
