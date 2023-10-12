#include "EfiDSEFix.h"
#include <ntstatus.h>

static
VOID
PrintUsage(
	_In_ PCWCHAR ProgramName
	)
{
	const BOOLEAN Win8OrHigher = (RtlNtMajorVersion() >= 6 && RtlNtMinorVersion() >= 2) || RtlNtMajorVersion() > 6;
	const PCWCHAR CiOptionsName = Win8OrHigher ? L"g_CiOptions" : L"g_CiEnabled";
	Printf(L"\nUsage: %ls <COMMAND>\n\n"
		L"Commands:\n"
		L"    -c, --check%17lsTest EFI SetVariable hook\n"
		L"    -r, --read%18lsRead current %ls value\n"
		L"    -d, --disable%15lsDisable DSE\n"
		L"    -e, --enable%ls%2ls(Re)enable DSE\n"
		L"    -i, --info%18lsDump system info\n",
		ProgramName, L"", L"",
		CiOptionsName, L"",
		(Win8OrHigher ? L" [g_CiOptions]" : L"              "),
		L"", L"");
}

int wmain(int argc, wchar_t** argv)
{
	NT_ASSERT(argc != 0);

	if (argc <= 1 || argc > 3 ||
		(argc == 3 && wcstoul(argv[2], nullptr, 16) == 0) ||
		wcsncmp(argv[1], L"-h", sizeof(L"-h") / sizeof(WCHAR) - 1) == 0 ||
		wcsncmp(argv[1], L"--help", sizeof(L"--help") / sizeof(WCHAR) - 1) == 0)
	{
		// Print help text
		PrintUsage(argv[0]);
		return 0;
	}

	// All remaining commands require admin privileges
	BOOLEAN SeSystemEnvironmentWasEnabled, SeDebugWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, TRUE, FALSE, &SeSystemEnvironmentWasEnabled);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Error: failed to acquire SE_SYSTEM_ENVIRONMENT_PRIVILEGE.\n%ls must be run as Administrator.\n", argv[0]);
		return Status;
	}
	Status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
	if (!NT_SUCCESS(Status))
	{
		Printf(L"Error: failed to acquire SE_DEBUG_PRIVILEGE.\n%ls must be run as Administrator.\n", argv[0]);
		return Status;
	}

	// Parse command line params
	const BOOLEAN Win8OrHigher = (RtlNtMajorVersion() >= 6 && RtlNtMinorVersion() >= 2) || RtlNtMajorVersion() > 6;
	const ULONG EnabledCiOptionsValue = Win8OrHigher ? 0x6 : CODEINTEGRITY_OPTION_ENABLED;
	const PCWCHAR CiOptionsName = Win8OrHigher ? L"g_CiOptions" : L"g_CiEnabled";
	ULONG CiOptionsValue;
	BOOLEAN ReadOnly = FALSE;

	if (wcsncmp(argv[1], L"-r", sizeof(L"-r") / sizeof(WCHAR) - 1) == 0 ||
		wcsncmp(argv[1], L"--read", sizeof(L"--read") / sizeof(WCHAR) - 1) == 0)
	{
		CiOptionsValue = 0;
		ReadOnly = TRUE;
		Printf(L"Querying %ls value...\n", CiOptionsName);
	}
	else if (wcsncmp(argv[1], L"-d", sizeof(L"-d") / sizeof(WCHAR) - 1) == 0 ||
		wcsncmp(argv[1], L"--disable", sizeof(L"--disable") / sizeof(WCHAR) - 1) == 0)
	{
		CiOptionsValue = 0;
		Printf(L"Disabling DSE...\n");
	}
	else if (wcsncmp(argv[1], L"-e", sizeof(L"-e") / sizeof(WCHAR) - 1) == 0 ||
		wcsncmp(argv[1], L"--enable", sizeof(L"--enable") / sizeof(WCHAR) - 1) == 0)
	{
		if (Win8OrHigher)
		{
			CiOptionsValue = argc == 3 ? wcstoul(argv[2], nullptr, 16) : EnabledCiOptionsValue;
			Printf(L"(Re)enabling DSE [%ls value = 0x%lX]...\n", CiOptionsName, CiOptionsValue);
		}
		else
		{
			CiOptionsValue = EnabledCiOptionsValue;
			Printf(L"(Re)enabling DSE...\n");
		}
	}
	else if (wcsncmp(argv[1], L"-c", sizeof(L"-c") / sizeof(WCHAR) - 1) == 0 ||
		wcsncmp(argv[1], L"--check", sizeof(L"--check") / sizeof(WCHAR) - 1) == 0)
	{
		Printf(L"Checking for working EFI SetVariable hook...\n");
		Status = TestSetVariableHook();
		if (NT_SUCCESS(Status)) // Any errors have already been printed
			Printf(L"Success.\n");
		goto Exit;
	}
	else if (wcsncmp(argv[1], L"-i", sizeof(L"-i") / sizeof(WCHAR) - 1) == 0 ||
		wcsncmp(argv[1], L"--info", sizeof(L"--info") / sizeof(WCHAR) - 1) == 0)
	{
		Status = DumpSystemInformation();
		goto Exit;
	}
	else
	{
		PrintUsage(argv[0]);
		Status = STATUS_INVALID_PARAMETER;
		goto Exit;
	}

	// Call EFI runtime SetVariable service and write new value to g_CiOptions/g_CiEnabled
	ULONG OldCiOptionsValue;
	Status = AdjustCiOptions(CiOptionsValue, &OldCiOptionsValue, ReadOnly);

	// Print result
	if (!NT_SUCCESS(Status))
	{
		Printf(L"AdjustCiOptions failed: 0x%08lX\n", Status);
	}
	else
	{
		if (ReadOnly)
			Printf(L"Success.");
		else
			Printf(L"Successfully %ls DSE. Original", CiOptionsValue == 0 ? L"disabled" : L"(re)enabled");
		Printf(L" %ls value: 0x%lX\n", CiOptionsName, OldCiOptionsValue);
	}

Exit:
	RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, SeSystemEnvironmentWasEnabled, FALSE, &SeSystemEnvironmentWasEnabled);
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, SeDebugWasEnabled, FALSE, &SeDebugWasEnabled);

	return Status;
}

DECLSPEC_NOINLINE
static
VOID
ParseCommandLine(
	_In_ PWCHAR CommandLine,
	_Out_opt_ PWCHAR* Argv,
	_Out_opt_ PWCHAR Arguments,
	_Out_ PULONG Argc,
	_Out_ PULONG NumChars
	)
{
	*NumChars = 0;
	*Argc = 1;

	// Copy the executable name and and count bytes
	PWCHAR p = CommandLine;
	if (Argv != nullptr)
		*Argv++ = Arguments;

	// Handle quoted executable names
	BOOLEAN InQuotes = FALSE;
	WCHAR c;
	do
	{
		if (*p == '"')
		{
			InQuotes = !InQuotes;
			c = *p++;
			continue;
		}

		++*NumChars;
		if (Arguments != nullptr)
			*Arguments++ = *p;
		c = *p++;
	} while (c != '\0' && (InQuotes || (c != ' ' && c != '\t')));

	if (c == '\0')
		--p;
	else if (Arguments != nullptr)
		*(Arguments - 1) = L'\0';

	// Iterate over the arguments
	InQuotes = FALSE;
	for (; ; ++*NumChars)
	{
		if (*p != '\0')
		{
			while (*p == ' ' || *p == '\t')
				++p;
		}
		if (*p == '\0')
			break; // End of arguments

		if (Argv != nullptr)
			*Argv++ = Arguments;
		++*Argc;

		// Scan one argument
		for (; ; ++p)
		{
			BOOLEAN CopyChar = TRUE;
			ULONG NumSlashes = 0;

			while (*p == '\\')
			{
				// Count the number of slashes
				++p;
				++NumSlashes;
			}

			if (*p == '"')
			{
				// If 2N backslashes before: start/end a quote. Otherwise copy literally
				if ((NumSlashes & 1) == 0)
				{
					if (InQuotes && p[1] == '"')
						++p; // Double quote inside a quoted string
					else
					{
						// Skip first quote and copy second
						CopyChar = FALSE; // Don't copy quote
						InQuotes = !InQuotes;
					}
				}
				NumSlashes >>= 1;
			}

			// Copy slashes
			while (NumSlashes--)
			{
				if (Arguments != nullptr)
					*Arguments++ = '\\';
				++*NumChars;
			}

			// If we're at the end of the argument, go to the next
			if (*p == '\0' || (!InQuotes && (*p == ' ' || *p == '\t')))
				break;

			// Copy character into argument
			if (CopyChar)
			{
				if (Arguments != nullptr)
					*Arguments++ = *p;
				++*NumChars;
			}
		}

		if (Arguments != nullptr)
			*Arguments++ = L'\0';
	}
}

NTSTATUS
NTAPI
NtProcessStartupW(
	_In_ PPEB Peb
	)
{
	// On Windows XP (heh...) rcx does not contain a PEB pointer, but garbage
	Peb = Peb != nullptr ? NtCurrentPeb() : NtCurrentTeb()->ProcessEnvironmentBlock; // And this turd is to get Resharper to shut up about assigning to Peb before reading from it. Note LHS == RHS

	// Get the command line from the startup parameters. If there isn't one, use the executable name
	const PRTL_USER_PROCESS_PARAMETERS Params = RtlNormalizeProcessParams(Peb->ProcessParameters);
	const PWCHAR CommandLineBuffer = Params->CommandLine.Buffer == nullptr || Params->CommandLine.Buffer[0] == L'\0'
		? Params->ImagePathName.Buffer
		: Params->CommandLine.Buffer;

	// Count the number of arguments and characters excluding quotes
	ULONG Argc, NumChars;
	ParseCommandLine(CommandLineBuffer,
					nullptr,
					nullptr,
					&Argc,
					&NumChars);

	// Allocate a buffer for the arguments and a pointer array
	const ULONG ArgumentArraySize = (Argc + 1) * sizeof(PVOID);
	PWCHAR *Argv = static_cast<PWCHAR*>(
		RtlAllocateHeap(RtlProcessHeap(),
						HEAP_ZERO_MEMORY,
						ArgumentArraySize + NumChars * sizeof(WCHAR)));
	if (Argv == nullptr)
		return NtTerminateProcess(NtCurrentProcess, STATUS_NO_MEMORY);

	// Copy the command line arguments
	ParseCommandLine(CommandLineBuffer,
					Argv,
					reinterpret_cast<PWCHAR>(&Argv[Argc + 1]),
					&Argc,
					&NumChars);

	// Call the main function and terminate with the exit status
	const NTSTATUS Status = wmain(static_cast<int>(Argc), Argv);
	return NtTerminateProcess(NtCurrentProcess, Status);
}
