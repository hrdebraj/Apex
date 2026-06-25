/*
 * BOF: Network Share Enumeration (NetView)
 *
 * Enumerates SMB shares on a target host using NetShareEnum.
 * If no target is specified, enumerates the local machine.
 *
 * Compile: x86_64-w64-mingw32-gcc -c netview.c -o netview.o
 *
 * Arguments (packed via BeaconDataParse):
 *   [wchar*] target  - (optional) remote hostname or IP; NULL for localhost
 */

#include <windows.h>
#include "../bof_api.h"

/* Share info level 1 */
typedef struct {
    LPWSTR shi1_netname;
    DWORD  shi1_type;
    LPWSTR shi1_remark;
} SHARE_INFO_1;

#define STYPE_DISKTREE  0x00000000
#define STYPE_PRINTQ    0x00000001
#define STYPE_DEVICE    0x00000002
#define STYPE_IPC       0x00000003
#define STYPE_SPECIAL   0x80000000

DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetShareEnum(LPWSTR, DWORD, LPBYTE *, DWORD, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);

static const char *share_type_str(DWORD type) {
    DWORD base = type & 0x0FFFFFFF;
    switch (base) {
        case STYPE_DISKTREE: return "DISK";
        case STYPE_PRINTQ:   return "PRINT";
        case STYPE_DEVICE:   return "DEVICE";
        case STYPE_IPC:      return "IPC";
        default:             return "UNKNOWN";
    }
}

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    wchar_t *target = NULL;
    if (BeaconDataLength(&parser) > 0)
        target = (wchar_t *)BeaconDataExtract(&parser, NULL);

    /* Ensure netapi32.dll is loaded */
    KERNEL32$LoadLibraryA("netapi32.dll");

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Enumerating shares on: %S",
                 target ? target : L"localhost");

    LPBYTE buf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;

    DWORD status = NETAPI32$NetShareEnum(
        target, 1, &buf, 0xFFFFFFFF,
        &entriesRead, &totalEntries, &resumeHandle
    );

    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "NetShareEnum failed: %lu", status);
        return;
    }

    if (entriesRead == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] No shares found");
        if (buf) NETAPI32$NetApiBufferFree(buf);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n  %-30s %-10s %s", "SHARE", "TYPE", "REMARK");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-30s %-10s %s", "-----", "----", "------");

    SHARE_INFO_1 *shares = (SHARE_INFO_1 *)buf;
    for (DWORD i = 0; i < entriesRead; i++) {
        const char *typeStr = share_type_str(shares[i].shi1_type);
        int hidden = (shares[i].shi1_type & STYPE_SPECIAL) ? 1 : 0;

        BeaconPrintf(CALLBACK_OUTPUT, "  %-30S %-10s%s %S",
            shares[i].shi1_netname,
            typeStr,
            hidden ? " [H]" : "    ",
            shares[i].shi1_remark ? shares[i].shi1_remark : L""
        );
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] %lu share(s) enumerated", entriesRead);

    NETAPI32$NetApiBufferFree(buf);
}
