/*
 * BOF: Extended Whoami (Token Info + Groups + Privileges)
 *
 * Queries the current thread/process token for user identity,
 * group memberships, and privilege listing.
 *
 * Compile: x86_64-w64-mingw32-gcc -c whoami_bof.c -o whoami_bof.o
 *
 * Arguments: none
 */

#include <windows.h>
#include "../bof_api.h"

DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS,
    LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$LookupAccountSidA(LPCSTR, PSID, LPSTR, LPDWORD,
    LPSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$LookupPrivilegeNameA(LPCSTR, PLUID, LPSTR, LPDWORD);

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetCurrentProcess(void);
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalFree(HGLOBAL);

static void print_user_info(HANDLE hToken) {
    DWORD cbSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, 0, &cbSize);

    TOKEN_USER *tokenUser = (TOKEN_USER *)KERNEL32$GlobalAlloc(0, cbSize);
    if (!tokenUser) return;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, tokenUser, cbSize, &cbSize)) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation(TokenUser) failed: %lu",
                     KERNEL32$GetLastError());
        KERNEL32$GlobalFree(tokenUser);
        return;
    }

    char name[256] = {0}, domain[256] = {0};
    DWORD nameLen = sizeof(name), domLen = sizeof(domain);
    SID_NAME_USE sidType;

    if (ADVAPI32$LookupAccountSidA(NULL, tokenUser->User.Sid, name, &nameLen,
                                    domain, &domLen, &sidType)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] User: %s\\%s", domain, name);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] User: (unknown)");
    }

    KERNEL32$GlobalFree(tokenUser);
}

static void print_groups(HANDLE hToken) {
    DWORD cbSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenGroups, NULL, 0, &cbSize);

    TOKEN_GROUPS *tokenGroups = (TOKEN_GROUPS *)KERNEL32$GlobalAlloc(0, cbSize);
    if (!tokenGroups) return;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenGroups, tokenGroups, cbSize, &cbSize)) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation(TokenGroups) failed: %lu",
                     KERNEL32$GetLastError());
        KERNEL32$GlobalFree(tokenGroups);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Group Memberships (%lu groups):", tokenGroups->GroupCount);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-50s %s", "GROUP", "ATTRIBUTES");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-50s %s", "-----", "----------");

    for (DWORD i = 0; i < tokenGroups->GroupCount; i++) {
        char name[256] = {0}, domain[256] = {0};
        DWORD nameLen = sizeof(name), domLen = sizeof(domain);
        SID_NAME_USE sidType;

        char attrs[128] = {0};
        DWORD a = tokenGroups->Groups[i].Attributes;
        if (a & SE_GROUP_ENABLED)            strncat(attrs, "Enabled ", sizeof(attrs) - strlen(attrs) - 1);
        if (a & SE_GROUP_ENABLED_BY_DEFAULT) strncat(attrs, "Default ", sizeof(attrs) - strlen(attrs) - 1);
        if (a & SE_GROUP_MANDATORY)          strncat(attrs, "Mandatory ", sizeof(attrs) - strlen(attrs) - 1);
        if (a & SE_GROUP_OWNER)              strncat(attrs, "Owner ", sizeof(attrs) - strlen(attrs) - 1);

        if (ADVAPI32$LookupAccountSidA(NULL, tokenGroups->Groups[i].Sid,
                                        name, &nameLen, domain, &domLen, &sidType)) {
            BeaconPrintf(CALLBACK_OUTPUT, "  %s\\%-43s %s", domain, name, attrs);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "  %-50s %s", "(unresolved SID)", attrs);
        }
    }

    KERNEL32$GlobalFree(tokenGroups);
}

static void print_privileges(HANDLE hToken) {
    DWORD cbSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &cbSize);

    TOKEN_PRIVILEGES *tokenPrivs = (TOKEN_PRIVILEGES *)KERNEL32$GlobalAlloc(0, cbSize);
    if (!tokenPrivs) return;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenPrivileges, tokenPrivs, cbSize, &cbSize)) {
        BeaconPrintf(CALLBACK_ERROR, "GetTokenInformation(TokenPrivileges) failed: %lu",
                     KERNEL32$GetLastError());
        KERNEL32$GlobalFree(tokenPrivs);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Privileges (%lu total):", tokenPrivs->PrivilegeCount);
    BeaconPrintf(CALLBACK_OUTPUT, "  %-45s %s", "PRIVILEGE", "STATE");
    BeaconPrintf(CALLBACK_OUTPUT, "  %-45s %s", "---------", "-----");

    for (DWORD i = 0; i < tokenPrivs->PrivilegeCount; i++) {
        char privName[256] = {0};
        DWORD privLen = sizeof(privName);

        if (ADVAPI32$LookupPrivilegeNameA(NULL, &tokenPrivs->Privileges[i].Luid,
                                           privName, &privLen)) {
            const char *state = "Disabled";
            if (tokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)
                state = "Enabled";
            if (tokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT)
                state = "Enabled (Default)";

            BeaconPrintf(CALLBACK_OUTPUT, "  %-45s %s", privName, state);
        }
    }

    KERNEL32$GlobalFree(tokenPrivs);
}

void go(char *args, int len) {
    (void)args; (void)len;

    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        BeaconPrintf(CALLBACK_ERROR, "OpenProcessToken failed: %lu", KERNEL32$GetLastError());
        return;
    }

    print_user_info(hToken);
    print_groups(hToken);
    print_privileges(hToken);

    KERNEL32$CloseHandle(hToken);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Done");
}
