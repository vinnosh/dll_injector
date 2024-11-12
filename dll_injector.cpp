#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <iomanip>
#include <Shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

DWORD GetProcId(const char* pn, unsigned short int fi = 0b1101)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (fi == 0b10100111001)
                    std::cout << pE.szExeFile << u8"\x9\x9\x9" << pE.th32ProcessID << std::endl;
                if (!_stricmp(pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    std::cout << "Process : 0x" << std::hex << pE.th32ProcessID << std::endl;
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

BOOL InjectDLL(DWORD procID, const char* dllPath)
{
    BOOL WPM = 0;

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procID);
    if (hProc == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WPM = WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);
    if (!WPM)
    {
        CloseHandle(hProc);
        return -1;
    }
    std::cout << "DLL Injected Successfully 0x" << std::hex << WPM << std::endl;
    HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
    if (!hThread)
    {
        VirtualFree(loc, strlen(dllPath) + 1, MEM_RELEASE);
        CloseHandle(hProc);
        return -1;
    }
    std::cout << "Thread Created Successfully 0x" << std::hex << hThread << std::endl;
    CloseHandle(hProc);
    VirtualFree(loc, strlen(dllPath) + 1, MEM_RELEASE);
    CloseHandle(hThread);
    return 0;
}

int wmain(void)
{
    std::string pname, dllpath;
    std::cout << "Process name (The name of process to inject): ";
    std::cin >> pname;
    std::cout << "DLL path (Full path to the desired DLL): ";
    std::cin >> dllpath;
    system("cls");

    if (PathFileExists(dllpath.c_str()) == FALSE)
    {
        std::cout << "DLL File does NOT exist!" << std::endl;
        return EXIT_FAILURE;
    }
    DWORD procId = 0;
    procId = GetProcId(pname.c_str());
    if (procId == NULL)
    {
        std::cout << "Process Not found (0x" << std::hex << GetLastError() << ")" << std::endl;
        std::cout << "Here is a list of available processes." << std::endl;
        Sleep(3500);
        system("cls");
        GetProcId("skinjbir", 0b10100111001);
    }
    else
        InjectDLL(procId, dllpath.c_str());

    system("pause");
    return EXIT_SUCCESS;
}
