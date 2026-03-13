/*
 * BOF API Compatibility Header
 *
 * Declares the Beacon API functions and types available to BOFs at runtime.
 * These symbols are resolved by the COFF loader (agent/bof.h) when the
 * BOF is executed in-memory. BOFs should include this header and NOT
 * link against any library — compile with:
 *
 *   x86_64-w64-mingw32-gcc -c bof.c -o bof.o
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

extern void  BeaconDataParse(datap *parser, char *buffer, int size);
extern int   BeaconDataInt(datap *parser);
extern short BeaconDataShort(datap *parser);
extern int   BeaconDataLength(datap *parser);
extern char *BeaconDataExtract(datap *parser, int *size);

/* ── Beacon output API ───────────────────────────────────── */

extern void BeaconOutput(int type, char *data, int len);
extern void BeaconPrintf(int type, char *fmt, ...);

/* ── Token API ───────────────────────────────────────────── */

extern BOOL BeaconUseToken(HANDLE token);
extern void BeaconRevertToken(void);
extern BOOL BeaconIsAdmin(void);

/* ── Process API ─────────────────────────────────────────── */

extern void BeaconGetSpawnTo(BOOL x86, char *buffer, int length);
extern BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken,
                                        STARTUPINFOA *si, PROCESS_INFORMATION *pi);
extern void BeaconInjectProcess(HANDLE hProcess, int pid, char *payload, int payloadLen,
                                int offset, char *arg, int argLen);
extern void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pi, char *payload, int payloadLen,
                                         int offset, char *arg, int argLen);

#endif /* BOF_API_H */
