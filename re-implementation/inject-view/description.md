# Section View Injection: Shared Section Shellcode Injection

## Technique

**MITRE ATT&CK:** T1055 - Process Injection (Section View Injection)

## Description

This tool injects raw shellcode (`.bin`) into a running target process by creating a shared **section object** and mapping it into both the injector and the target process. The payload is copied into the local mapped view and becomes executable in the remote mapped view. Execution is triggered via `RtlCreateUserThread`.

## Execution Flow

```mermaid
flowchart TD
    A[Start] --> B[Read shellcode.bin into buffer]
    B --> C[Find target process PID by name]
    C --> D[OpenProcess with VM/Thread rights]
    D --> E[NtCreateSection\nSEC_COMMIT + RWX]
    E --> F[NtMapViewOfSection\nMap local view (RW)]
    F --> G[memcpy\nCopy shellcode into local view]
    G --> H[NtMapViewOfSection\nMap remote view (RX)]
    H --> I[RtlCreateUserThread\nStartAddress = remote view]
    I --> J[Shellcode executes\nin target process]
    J --> K[End]
```

### Steps Detail

| Step | API Call(s)                                        | Description                                                         |
| ---- | -------------------------------------------------- | ------------------------------------------------------------------- |
| 1    | `CreateFileA` / `ReadFile`                         | Read shellcode from `.bin` file into local memory                   |
| 2    | `CreateToolhelp32Snapshot` / `Process32First/Next` | Find target process PID by name (default: `notepad.exe`)            |
| 3    | `OpenProcess`                                      | Open target process with injection-related access rights            |
| 4    | `NtCreateSection`                                  | Create a section object large enough for the payload                |
| 5    | `NtMapViewOfSection`                               | Map section into the injector process (RW)                          |
| 6    | `memcpy`                                           | Copy shellcode into local mapped view                               |
| 7    | `NtMapViewOfSection`                               | Map same section into target process (RX)                           |
| 8    | `RtlCreateUserThread`                              | Create a thread in target process to execute at remote view address |

## Payload Requirements

- Format: Raw binary (`.bin`), not PE
- Architecture: Must match the target process (x64 shellcode → x64 process, x86 → x86)
- Position-independent code (PIC)
- Entry point at first byte

## Usage

```
InjectView_FileLoader.exe <shellcode.bin> <target_process_name>
```

Examples:

```
InjectView_FileLoader.exe payload.bin notepad.exe
InjectView_FileLoader.exe payload.bin explorer.exe
```

## IOCs for Detection

- Cross-process shared section mapping + remote thread start at a non-module address
- Executable private memory in target backed by a section object (not a file image mapping)
- API sequence: OpenProcess → NtCreateSection → NtMapViewOfSection (local) → NtMapViewOfSection (remote) → RtlCreateUserThread

## Log Sources Coverage

| Data Component            | Log Source                           | Channel/Event                                        | Detected?                                                                                 |
| ------------------------- | ------------------------------------ | ---------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| Process Creation (DC0032) | WinEventLog:Sysmon                   | EventCode=1                                          | ❌ No (target already running)                                                            |
| Process Access (DC0035)   | WinEventLog:Sysmon                   | EventCode=10                                         | ✅ Yes (injector opens target with VM/thread rights)                                      |
| Module Load (DC0016)      | WinEventLog:Sysmon                   | EventCode=7                                          | ⚠️ Maybe (only if Sysmon ImageLoad is enabled; mostly normal DLL loads)                   |
| Process Thread (DC0029)   | WinEventLog:Sysmon                   | EventCode=8                                          | ⚠️ Maybe (depends on Sysmon config; uses `RtlCreateUserThread`, not `CreateRemoteThread`) |
| OS API Execution (DC0021) | etw:Microsoft-Windows-Kernel-Process | NtCreateSection, NtMapViewOfSection, thread creation | ✅ Yes (if ETW collection enabled)                                                        |

> **Note:** This technique avoids `VirtualAllocEx` + `WriteProcessMemory` by using a shared section, but still results in executable memory and remote execution in the target process.
