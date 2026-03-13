/*
 * BOF API Compatibility Header
 *
 * Declares the Beacon API functions and types available to BOFs at runtime.
 * These symbols are resolved by the COFF loader (agent/bof.h) when the
 * BOF is executed in-memory. BOFs should include this header and NOT
 * link against any library — compile with:
 *
 *   x86_64-w64-mingw32-gcc -c bof.c -o bof.o
 *
 * IMPORTANT: All functions use DECLSPEC_IMPORT so the compiler generates
 * __imp_-prefixed symbols. The loader resolves these through IAT entries,
 * which avoids REL32 overflow on x86_64 when the agent image is >2GB
 * away from VirtualAlloc'd BOF code.
 */

#ifndef BOF_API_H
#define BOF_API_H

#include <windows.h>

/* ── Callback type constants ─────────────────────────────── */

#define CALLBACK_OUTPUT 0x00
#define CALLBACK_ERROR  0x0d

/* ── Data parser ─────────────────────────────────────────── */

typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

/* ── Beacon data API ─────────────────────────────────────── */

DECLSPEC_IMPORT void  BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int   BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int   BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);

/* ── Beacon output API ───────────────────────────────────── */

DECLSPEC_IMPORT void BeaconOutput(int type, char *data, int len);
DECLSPEC_IMPORT void BeaconPrintf(int type, char *fmt, ...);

/* ── Token API ───────────────────────────────────────────── */

DECLSPEC_IMPORT BOOL BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL BeaconIsAdmin(void);

/* ── Process API ─────────────────────────────────────────── */

DECLSPEC_IMPORT void BeaconGetSpawnTo(BOOL x86, char *buffer, int length);
DECLSPEC_IMPORT BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                        STARTUPINFOA *si, PROCESS_INFORMATION *pi);
DECLSPEC_IMPORT void BeaconInjectProcess(HANDLE hProcess, int pid, char *payload, int payloadLen,
                                int offset, char *arg, int argLen);
DECLSPEC_IMPORT void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pi, char *payload, int payloadLen,
                                         int offset, char *arg, int argLen);

#endif /* BOF_API_H */
