/*
 * gen_shellcode — Combines PIC stub + PE/DLL into raw shellcode
 *
 * This runs on the BUILD HOST (Linux/macOS), not Windows.
 *
 * Usage: ./gen_shellcode <pic_stub.bin> <agent.dll> <output.bin>
 *
 * 1. Reads the PIC stub raw binary
 * 2. Reads the PE (DLL) file
 * 3. Finds the 8-byte marker 0x4150455850454F46 ("APEXPEOF") in the stub
 * 4. Replaces it with the stub size (= offset from shellcode start to PE data)
 * 5. Writes stub + PE concatenated as output
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MARKER 0x4150455850454F46ULL  /* "APEXPEOF" in little-endian */

static unsigned char *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    unsigned char *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return NULL;
    }
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <pic_stub.bin> <agent.dll> <output.bin>\n", argv[0]);
        return 1;
    }

    size_t stub_size = 0, pe_size = 0;
    unsigned char *stub = read_file(argv[1], &stub_size);
    unsigned char *pe   = read_file(argv[2], &pe_size);
    if (!stub || !pe) {
        fprintf(stderr, "Failed to read input files\n");
        return 1;
    }

    /* Find the marker in the stub */
    int found = 0;
    for (size_t i = 0; i <= stub_size - 8; i++) {
        uint64_t val;
        memcpy(&val, stub + i, 8);
        if (val == MARKER) {
            /*
             * Patch with distance FROM the marker TO the PE data.
             * The stub code reads &g_pe_offset (which is at stub+i at runtime)
             * and adds this value: &marker + offset_from_marker = PE start.
             */
            uint64_t offset_from_marker = (uint64_t)(stub_size - i);
            memcpy(stub + i, &offset_from_marker, 8);
            found = 1;
            printf("[*] Marker at stub+0x%zx, patched offset = %llu (stub=%zu, PE starts at +%zu)\n",
                   i, (unsigned long long)offset_from_marker, stub_size, stub_size);
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "[!] Marker 0x%llx not found in stub — writing unpatched\n",
                (unsigned long long)MARKER);
    }

    /* Write combined output */
    FILE *out = fopen(argv[3], "wb");
    if (!out) { perror(argv[3]); return 1; }
    fwrite(stub, 1, stub_size, out);
    fwrite(pe, 1, pe_size, out);
    fclose(out);

    printf("[+] Shellcode: %s (%zu bytes = %zu stub + %zu PE)\n",
           argv[3], stub_size + pe_size, stub_size, pe_size);

    free(stub);
    free(pe);
    return 0;
}
