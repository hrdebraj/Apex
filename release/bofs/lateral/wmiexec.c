/*
 * BOF: WMI Remote Command Execution
 *
 * Executes a command on a remote host via WMI (Win32_Process.Create).
 * Compile: x86_64-w64-mingw32-gcc -c wmiexec.c -o wmiexec.o
 *
 * Arguments (packed via BeaconDataParse):
 *   [wchar*] target   - remote hostname or IP
 *   [wchar*] command  - command to execute
 */

#include <windows.h>
#include "../bof_api.h"

#define COINIT_MULTITHREADED 0

typedef HRESULT (WINAPI *pCoInitializeEx)(LPVOID, DWORD);
typedef HRESULT (WINAPI *pCoInitializeSecurity)(PSECURITY_DESCRIPTOR, LONG, void*, void*, DWORD, DWORD, void*, DWORD, void*);
typedef HRESULT (WINAPI *pCoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef void    (WINAPI *pCoUninitialize)(void);

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    wchar_t *target  = (wchar_t *)BeaconDataExtract(&parser, NULL);
    wchar_t *command = (wchar_t *)BeaconDataExtract(&parser, NULL);

    if (!target || !command) {
        BeaconPrintf(CALLBACK_ERROR, "Usage: wmiexec <target> <command>");
        return;
    }

    HMODULE hOle32 = KERNEL32$LoadLibraryA("ole32.dll");
    if (!hOle32) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to load ole32.dll");
        return;
    }

    pCoInitializeEx fnInit = (pCoInitializeEx)KERNEL32$GetProcAddress(hOle32, "CoInitializeEx");
    pCoUninitialize fnUninit = (pCoUninitialize)KERNEL32$GetProcAddress(hOle32, "CoUninitialize");

    if (!fnInit || !fnUninit) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve COM functions");
        return;
    }

    HRESULT hr = fnInit(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_ERROR, "CoInitializeEx failed: 0x%08lx", hr);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] WMI exec target: %S\n"
        "[*] Command: %S\n"
        "[!] Full COM/WMI IDispatch implementation required.\n"
        "    This template demonstrates the BOF structure.\n"
        "    For production use, implement IWbemLocator->ConnectServer.\n",
        target, command);

    fnUninit();
}
