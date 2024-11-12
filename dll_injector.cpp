#include <iostream>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

#ifdef __linux__
#include <unistd.h>  // For Linux-specific headers
#include <sys/types.h>
#include <sys/wait.h>
#include <iostream>
#endif  

void InjectDLL(const char* dllPath) {
    #ifdef _WIN32
    // Windows-specific code for DLL injection

    DWORD procId = 0;
    const char* targetProcess = "mspaint.exe";  // Example: Inject into mspaint

    // Get the process ID of the target process
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE)) {
            do {
                if (!_stricmp(pE.szExeFile, targetProcess)) {
                    procId = pE.th32ProcessID;
                    std::cout << "Found process: " << pE.szExeFile << " with PID: " << procId << std::endl;
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
        CloseHandle(hSnap);
    }

    if (procId == 0) {
        std::cout << "Target process not found!" << std::endl;
        return;
    }

    // Open the target process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
    if (hProc == NULL) {
        std::cout << "Failed to open process!" << std::endl;
        return;
    }

    // Allocate memory for the DLL path
    void* loc = VirtualAllocEx(hProc, 0, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0);

    // Get the address of LoadLibraryA
    FARPROC loadLibAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    // Create a remote thread in the target process to call LoadLibraryA
    CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, loc, 0, NULL);

    // Clean up
    CloseHandle(hProc);
    VirtualFreeEx(hProc, loc, 0, MEM_RELEASE);
    std::cout << "DLL injection completed successfully!" << std::endl;
    #endif

    #ifdef __linux__
    // Linux-specific code (Process manipulation using fork and exec)

    std::cout << "Injecting process on Linux..." << std::endl;

    pid_t pid = fork();  // Create a new process
    if (pid == -1) {
        std::cerr << "Fork failed!" << std::endl;
        return;
    }

    if (pid == 0) {
        // Child process: this will be the injected process
        std::cout << "Child process: Executing the target binary." << std::endl;
        
        // Replace the current process with a new process (for example, /bin/echo)
        execlp("/bin/echo", "echo", "Hello from injected process!", nullptr);
    } else {
        // Parent process: waiting for child to complete
        std::cout << "Parent process: Waiting for child process to complete." << std::endl;
        wait(NULL);  // Wait for the child process to finish
        std::cout << "Child process completed." << std::endl;
    }
    #endif
}

int main() {
    const char* dllPath = "C:\\path\\to\\your\\dll.dll";  // Windows path for DLL

    // For Linux, you can pass a different path or target.
    // Example for Linux: You might want to pass the name of a binary or another path.

    InjectDLL(dllPath);
    return 0;
}
