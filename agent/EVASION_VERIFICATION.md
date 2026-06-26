# Evasion Feature Verification Checklist

Step-by-step guide to verify each evasion feature is working on a live Windows target.
All tests assume the agent is compiled with default flags (all features enabled).

---

## Prerequisites

### Required Tools (install on the Windows test machine)

| Tool | Purpose | Source |
|------|---------|--------|
| **Process Hacker 2** | Memory inspection, thread stacks, handles, modules | processhacker.sourceforge.io |
| **x64dbg** | Debugger for stepping through syscalls and ROP chains | x64dbg.com |
| **Pe-sieve** | Detects hollowed/stomped PE headers, hooked modules | github.com/hasherezade/pe-sieve |
| **Moneta** | Memory scanner for injected/unbacked executable regions | github.com/forrest-orr/moneta |
| **Process Monitor** | Logs API calls, file/registry activity in real time | learn.microsoft.com/sysinternals |
| **API Monitor** | Intercept and log Win32/NT API calls per-process | rohitab.com/apimonitor |
| **PowerShell** | ETW/AMSI testing, built-in | Built-in |
| **Strings** (Sysinternals) | Extract printable strings from binary | learn.microsoft.com/sysinternals |
| **WinDbg** (optional) | Kernel-level debugging for syscall verification | learn.microsoft.com |

### Build Variants

Build three agent binaries for testing different sleep methods:

```bash
# On the build machine (Linux/WSL)
cd agent

# Default: Ekko sleep
make clean && make exe
cp agent.exe agent_ekko.exe

# Foliage sleep
make clean && SLEEP_METHOD=2 make exe
cp agent.exe agent_foliage.exe

# Plain sleep (baseline)
make clean && SLEEP_METHOD=0 make exe
cp agent.exe agent_plain.exe
```

### Test Environment

- Windows 10/11 VM with Defender **disabled** for initial functional testing
- Snapshot the VM before testing
- Run agent as Administrator for full feature coverage
- Have the teamserver running and reachable from the VM

---

## 1. Binary Hygiene (Pre-Execution)

### 1.1 No IOC strings in binary

```powershell
# Run on the compiled .exe
strings.exe -n 5 agent.exe | Select-String -Pattern "beacon|cobalt|meterp|mimikatz|rundll32|bof_|ntcontinue|systemfunction|amsi|EtwEvent" -CaseSensitive:$false
```

- [ ] **PASS**: Zero matches. No suspicious strings visible.

### 1.2 Symbols stripped

```powershell
# Check for debug symbols / function names
strings.exe agent.exe | Select-String -Pattern "^(Gate_|patch_|rop_sleep|spoof_call|synth_frame|heap_xor|drip_alloc)"
```

- [ ] **PASS**: Zero matches. The `-s` strip flag removed all symbols.

### 1.3 PE subsystem is GUI (no console window)

```powershell
# Using dumpbin (from VS Developer Command Prompt)
dumpbin /headers agent.exe | Select-String "subsystem"
# Or use CFF Explorer / PE-bear to check Optional Header -> Subsystem
```

- [ ] **PASS**: Shows `WINDOWS GUI` (subsystem 2), not `CONSOLE`.

### 1.4 No console window on launch

- [ ] Double-click `agent.exe` on the desktop
- [ ] **PASS**: No black console window appears
- [ ] **PASS**: Agent appears under "Background processes" in Task Manager, not "Apps"

---

## 2. ETW Patch (`ENABLE_ETW_PATCH`)

### What it does
Patches `ntdll!EtwEventWrite` to `sub eax,eax; ret` so all ETW telemetry from the process is silenced.

### Verify

**Method A: x64dbg**

1. Attach x64dbg to `agent.exe`
2. Go to `ntdll.dll` -> find `EtwEventWrite`
3. Check the first bytes at the entry point

```
# Expected (patched):
EtwEventWrite:
  2B C0    sub eax, eax
  C3       ret
```

- [ ] **PASS**: First 3 bytes are `2B C0 C3`

**Method B: PowerShell ETW consumer**

```powershell
# In an admin PowerShell, start an ETW trace BEFORE launching agent
logman create trace ApexTest -p Microsoft-Windows-Kernel-Process -o C:\etw_test.etl -ets
# Launch agent.exe
# Wait 30 seconds, then stop
logman stop ApexTest -ets
# Check if events from agent PID appear
tracerpt C:\etw_test.etl -o C:\etw_report.xml -of XML
# Search the report for the agent's PID
```

- [ ] **PASS**: No ETW events from the agent PID after the patch fires

---

## 3. AMSI Patch (`ENABLE_AMSI_PATCH`)

### What it does
Patches `amsi.dll!AmsiScanBuffer` to return `E_INVALIDARG (0x80070057)` immediately, disabling AMSI scanning in the process.

### Verify

**Method A: x64dbg**

1. Attach to `agent.exe`
2. Navigate to `amsi.dll` -> `AmsiScanBuffer`
3. Check entry bytes

```
# Expected (patched):
AmsiScanBuffer:
  B8 57 00 07 80   mov eax, 0x80070057
  C3               ret
```

- [ ] **PASS**: First 6 bytes are `B8 57 00 07 80 C3`

**Method B: API Monitor**

1. Launch API Monitor, filter for `AmsiScanBuffer`
2. Attach to `agent.exe`
3. Trigger any BOF execution from the C2 client

- [ ] **PASS**: `AmsiScanBuffer` returns `0x80070057` for every call

---

## 4. Ntdll Unhooking (`ENABLE_UNHOOK`)

### What it does
Reads a clean copy of `ntdll.dll` from `C:\Windows\System32\ntdll.dll` on disk and overwrites the in-memory `.text` section, removing any EDR hooks.

### Verify

**Method A: Pe-sieve**

```powershell
# Run pe-sieve BEFORE agent starts (baseline — see what hooks exist from EDR)
pe-sieve.exe /pid:<explorer_pid> /shellc /hooks

# Launch agent.exe, note its PID
# Run pe-sieve on the agent
pe-sieve.exe /pid:<agent_pid> /shellc /hooks
```

- [ ] **PASS**: Pe-sieve reports 0 hooked modules / 0 patches in ntdll for the agent process
- [ ] **COMPARE**: Other processes (without unhooking) show EDR hooks in ntdll

**Method B: Manual byte comparison in x64dbg**

1. Attach x64dbg to `agent.exe`
2. Go to `ntdll.dll` -> any known-hooked function (e.g., `NtAllocateVirtualMemory`)
3. Compare prologue bytes with the on-disk copy

- [ ] **PASS**: In-memory ntdll matches the on-disk original (no JMP/detour patches)

---

## 5. Indirect Syscalls (`ENABLE_INDIRECT_SYSCALL`)

### What it does
Resolves SSNs via HellsGate (disk) / HalosGate (memory), generates per-syscall stubs with baked-in SSNs, and executes `syscall` from our own RX page — not from ntdll.

### Verify

**Method A: x64dbg — inspect stub page**

1. Attach x64dbg to `agent.exe`
2. Open Memory Map (Alt+M)
3. Look for a small RX allocation (not in any DLL) — this is `g_stub_page`
4. Inspect the bytes — each 11-byte stub should follow the pattern:

```
B8 xx xx 00 00   ; mov eax, <SSN>
4C 8B D1         ; mov r10, rcx
0F 05            ; syscall
C3               ; ret
```

5. Verify SSN values against known SSN tables for your Windows build

- [ ] **PASS**: Stub page exists with correct 11-byte per-syscall stubs
- [ ] **PASS**: SSNs match expected values for the OS version

**Method B: Set breakpoint on syscall**

1. In x64dbg, set hardware breakpoint on the `syscall` instruction in one of the stubs
2. Trigger a command from the C2 (e.g., `ls`, `whoami`)
3. Observe the hit

- [ ] **PASS**: Breakpoint hits in our stub page, not inside `ntdll.dll`
- [ ] **PASS**: `eax` contains the correct SSN at the `syscall` instruction
- [ ] **PASS**: Return address on stack points to our code, not ntdll

**Method C: API Monitor — negative test**

1. Hook `NtAllocateVirtualMemory`, `NtCreateThreadEx` in API Monitor
2. Trigger agent activity

- [ ] **PASS**: API Monitor does NOT capture these calls (they bypass the API layer via direct syscall)

---

## 6. Ekko Sleep (`SLEEP_METHOD=1`)

### What it does
Timer-queue ROP chain: 5 timers with `NtContinue` as callback encrypt .text with RC4 via `SystemFunction032`, flip permissions to RW during sleep, then decrypt and restore RX on wake.

### Verify

**Method A: Process Hacker — memory protection during sleep**

1. Launch `agent_ekko.exe`, note PID
2. Open Process Hacker -> double-click the process -> Memory tab
3. Locate the main `.text` section (look for the image base)
4. **While the agent is sleeping** (between callbacks), check the protection column

- [ ] **PASS**: .text shows `RW` (Read/Write) during sleep, NOT `RX`

5. Wait for agent to wake (next callback cycle), check again

- [ ] **PASS**: .text returns to `RX` (Read/Execute) after waking

**Method B: Moneta — scan during sleep**

```powershell
# While agent is sleeping:
Moneta64.exe -p <agent_pid>
```

- [ ] **PASS**: Moneta does NOT flag the .text section as suspicious during sleep (it's RW, not RWX, and not executable)

**Method C: Memory dump during sleep**

1. Use Process Hacker -> right-click process -> Create Dump File (while sleeping)
2. Run `strings` on the dump
3. Compare with a dump taken while awake

- [ ] **PASS**: .text content in the sleep dump is garbled (RC4 encrypted)
- [ ] **PASS**: .text content in the awake dump is valid code

**Method D: Timer queue visible in handles**

1. Process Hacker -> Handles tab for agent process
2. Look for Timer and Event handles

- [ ] **PASS**: Timer queue handles exist during the sleep cycle

---

## 7. Foliage Sleep (`SLEEP_METHOD=2`)

### What it does
APC-based ROP: creates a sacrificial thread, queues 6 APCs via `QueueUserAPC` with `NtContinue` to encrypt .text, sleep via `NtDelayExecution`, decrypt, and signal the main thread.

### Verify

**Method A: Process Hacker — thread count during sleep**

1. Launch `agent_foliage.exe`
2. Process Hacker -> Threads tab
3. Watch thread count during sleep cycle

- [ ] **PASS**: A sacrificial thread appears briefly during sleep (running `SleepEx`)
- [ ] **PASS**: Thread disappears after sleep completes

**Method B: Memory protection (same as Ekko)**

- [ ] **PASS**: .text is `RW` during sleep
- [ ] **PASS**: .text returns to `RX` after wake

**Method C: x64dbg — APC queue**

1. Set breakpoint on `QueueUserAPC`
2. Observe 6 calls queued sequentially
3. Set breakpoint on `NtContinue`
4. Step through each APC firing

- [ ] **PASS**: 6 APCs queued (VirtualProtect, RC4, NtDelayExecution, RC4, VirtualProtect, SetEvent)
- [ ] **PASS**: Each APC context has correct Rip pointing to the target function

---

## 8. Heap Encryption (`ENABLE_HEAP_ENCRYPT`)

### What it does
XOR-encrypts registered heap regions (C2 config, buffers, keys) with an 8-byte random key during every sleep cycle.

### Verify

**Method A: Memory search during sleep vs awake**

1. In Process Hacker or x64dbg, search process memory for a known string (e.g., the C2 host IP `127.0.0.1` or the registration path)
2. Search while agent is **awake** (processing tasks)
3. Search while agent is **sleeping**

- [ ] **PASS**: String found in memory while awake
- [ ] **PASS**: String NOT found in memory while sleeping (XOR-encrypted)

**Method B: Compare memory dumps**

```powershell
# Dump while awake
procdump.exe -ma <pid> awake.dmp
# Dump while sleeping
procdump.exe -ma <pid> sleep.dmp
# Search both
strings.exe awake.dmp | findstr /i "127.0.0.1"
strings.exe sleep.dmp | findstr /i "127.0.0.1"
```

- [ ] **PASS**: Awake dump contains the C2 host; sleep dump does not

---

## 9. Return Address Spoofing (`ENABLE_RET_ADDR_SPOOF`)

### What it does
Uses a JMP RBX gadget found in kernel32/ntdll so that when the target function returns, the stack shows a kernel32/ntdll address as the return address instead of our code.

### Verify

**Method A: x64dbg — check return address during spoofed call**

1. Set breakpoint at the start of a function called via `spoof_call`
2. When it hits, examine the stack (`rsp`)

```
# Expected stack layout at function entry:
[rsp]    -> address inside kernel32.dll .text (the JMP RBX gadget)
[rsp+8]  -> shadow space
...
```

- [ ] **PASS**: Return address on stack points to kernel32/ntdll .text, not to our agent code

3. Also check RBX register:

- [ ] **PASS**: RBX contains our continuation address (label 1f)

**Method B: x64dbg — locate the gadget**

1. In x64dbg, search kernel32.dll .text for `FF E3` (JMP RBX)
2. Note the address
3. Set breakpoint on it
4. Trigger a spoofed call

- [ ] **PASS**: Gadget breakpoint hits after the target function returns
- [ ] **PASS**: After `JMP RBX`, execution continues in our agent code

---

## 10. Synthetic Stack Frames (`ENABLE_SYNTHETIC_FRAMES`)

### What it does
Before sleeping, overwrites RBP with a fake frame chain pointing to `RtlUserThreadStart` -> `BaseThreadInitThunk`, making the call stack look like a normal Windows thread.

### Verify

**Method A: Process Hacker — thread call stack during sleep**

1. Process Hacker -> double-click agent process -> Threads tab
2. Double-click the main thread
3. View the call stack **while the agent is sleeping**

- [ ] **PASS**: Stack shows `ntdll!RtlUserThreadStart` and `kernel32!BaseThreadInitThunk` frames
- [ ] **PASS**: No frames pointing to unbacked (agent) memory regions

**Method B: x64dbg — inspect RBP chain during sleep**

1. Break into agent while sleeping
2. Walk the RBP chain manually:

```
rbp -> [frame_buf+0]  = next RBP (frame_buf+16)
       [frame_buf+8]  = BaseThreadInitThunk address
       [frame_buf+16] = 0 (chain end)
       [frame_buf+24] = RtlUserThreadStart address
```

- [ ] **PASS**: RBP chain terminates at RtlUserThreadStart
- [ ] **PASS**: All return addresses in the chain resolve to legitimate Windows DLLs

---

## 11. PE Header Stomping (`ENABLE_PE_STOMP`)

### What it does
Overwrites MZ/PE magic bytes and header fields in the agent's own in-memory image after initialization, defeating PE scanners.

### Verify

**Method A: Pe-sieve**

```powershell
pe-sieve.exe /pid:<agent_pid> /data 2
```

- [ ] **PASS**: Pe-sieve reports the module as "header modified" or fails to parse it
- [ ] **PASS**: Pe-sieve cannot reconstruct the PE from memory

**Method B: Process Hacker — raw memory**

1. Process Hacker -> Memory tab -> find the agent's image base
2. Read the first 2 bytes

- [ ] **PASS**: NOT `4D 5A` (MZ magic is zeroed/overwritten)
- [ ] **PASS**: PE signature area is also corrupted

**Method C: x64dbg memory dump**

```
# In x64dbg command line:
db <image_base> L100
```

- [ ] **PASS**: First bytes are zeroed or randomized, not `4D 5A 90 00`

---

## 12. Block Non-Microsoft DLLs (`ENABLE_BLOCK_DLLS`)

### What it does
Sets `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES` on child processes, preventing EDR DLLs from injecting.

### Verify

**Method A: Process Hacker — child process modules**

1. From the C2, run a command that spawns a child (e.g., `shell whoami`)
2. Quickly open Process Hacker -> find the child `cmd.exe` process
3. Check the Modules tab

- [ ] **PASS**: Only Microsoft-signed DLLs loaded (ntdll, kernel32, kernelbase, msvcrt, etc.)
- [ ] **PASS**: No EDR DLLs (e.g., no CrowdStrike, SentinelOne, Cylance DLLs)

**Method B: Process Monitor**

1. Run ProcMon with filter: `Process Name = cmd.exe`, `Operation = Load Image`
2. Trigger a shell command from C2

- [ ] **PASS**: Only Microsoft-signed images loaded

---

## 13. Argument Spoofing (`ENABLE_ARG_SPOOF`)

### What it does
Creates the child process with a benign command line, then overwrites the real command line in the PEB before resuming.

### Verify

**Method A: Process Hacker — PEB command line**

1. From C2, run `shell ipconfig /all`
2. In Process Hacker, find the child process
3. Check the "Command line" field in the process properties

- [ ] **PASS**: Shows a benign/spoofed command line, NOT `ipconfig /all`

**Method B: Process Monitor**

1. ProcMon filter: `Operation = Process Create`
2. Trigger command from C2
3. Check the "Command Line" column

- [ ] **PASS**: Process creation event shows the spoofed (benign) command line

**Method C: WMI query**

```powershell
Get-WmiObject Win32_Process | Where-Object {$_.Name -eq "cmd.exe"} | Select-Object CommandLine
```

- [ ] **PASS**: Command line shows spoofed value

---

## 14. NtCreateUserProcess (`ENABLE_NT_PROCESS`)

### What it does
Uses the `NtCreateUserProcess` syscall directly instead of `CreateProcessA`, bypassing kernel32-level ETW events and API hooks.

### Verify

**Method A: API Monitor — negative test**

1. Hook `CreateProcessA`, `CreateProcessW`, `CreateProcessInternalW` in API Monitor
2. Attach to agent
3. Trigger a command from C2

- [ ] **PASS**: None of the `CreateProcess*` APIs are called
- [ ] **PASS**: Child process is still created (visible in Task Manager)

**Method B: ETW trace**

```powershell
# Start kernel process provider trace
logman create trace ProcTest -p Microsoft-Windows-Kernel-Process 0x10 -o C:\proc_test.etl -ets
# Trigger command from C2
# Stop trace
logman stop ProcTest -ets
tracerpt C:\proc_test.etl -o C:\proc_report.xml -of XML
```

- [ ] **PASS**: Fewer/no Win32-layer process creation events for agent-spawned children compared to normal `CreateProcess` calls

---

## 15. UDRL - User-Defined Reflective Loader (`ENABLE_UDRL`)

### What it does
Maps DLLs manually (resolve imports, relocations) without registering in the PEB's `InLoadOrderModuleList`, making them invisible to standard module enumeration.

### Verify (when loading BOFs/DLLs reflectively)

**Method A: Process Hacker modules list**

1. Load a BOF or reflective DLL via C2
2. Check Process Hacker -> Modules tab

- [ ] **PASS**: The reflectively loaded module does NOT appear in the module list

**Method B: Moneta scan**

```powershell
Moneta64.exe -p <agent_pid>
```

- [ ] **PASS**: Moneta may flag unbacked executable regions (expected), but there is no named module entry

---

## 16. Drip Allocation (`ENABLE_DRIP_LOAD`)

### What it does
Allocates memory in small increments instead of one large `VirtualAlloc`, evading scanners that flag large RWX allocations.

### Verify

**Method A: API Monitor**

1. Hook `VirtualAlloc` in API Monitor
2. Trigger a BOF load or large allocation from C2
3. Check the logged calls

- [ ] **PASS**: Multiple small `VirtualAlloc` calls instead of one large one
- [ ] **PASS**: Individual allocations are below typical scanner thresholds

---

## Defender Integration Test

After verifying all features individually with Defender disabled, run the final test:

### 17. Full Defender scan

1. Re-enable Windows Defender (Real-time protection ON)
2. Copy `agent.exe` to the desktop
3. Right-click -> "Scan with Microsoft Defender"

- [ ] **PASS**: No detection on static scan

4. Run `agent.exe` with the teamserver active
5. Let it beacon for 5+ minutes
6. Check Windows Security -> Virus & threat protection -> Protection history

- [ ] **PASS**: No runtime detection
- [ ] **PASS**: Agent maintains stable callbacks

7. Run a few commands from the C2 (`whoami`, `ls`, `ps`)

- [ ] **PASS**: Commands execute without triggering Defender
- [ ] **PASS**: No alerts in Event Viewer -> Windows Logs -> Security or Application

---

## Quick Reference: What to Check Where

| Feature | Primary Tool | What to Look For |
|---------|-------------|------------------|
| ETW patch | x64dbg | First 3 bytes of `EtwEventWrite` = `2B C0 C3` |
| AMSI patch | x64dbg | First 6 bytes of `AmsiScanBuffer` = `B8 57 00 07 80 C3` |
| Unhook | pe-sieve | 0 hooked modules in ntdll |
| Syscall stubs | x64dbg Memory Map | RX page with 11-byte stubs (`B8 xx xx 00 00 4C 8B D1 0F 05 C3`) |
| Ekko/Foliage | Process Hacker Memory | .text = RW during sleep, RX when awake |
| Heap encrypt | x64dbg memory search | C2 strings absent during sleep |
| Ret addr spoof | x64dbg stack | Return addr points to kernel32/ntdll |
| Synth frames | Process Hacker thread stack | Stack shows RtlUserThreadStart chain |
| PE stomp | x64dbg / pe-sieve | No MZ/PE magic at image base |
| Block DLLs | Process Hacker child modules | Only MS-signed DLLs in child |
| Arg spoof | Process Hacker / ProcMon | PEB command line is spoofed |
| NtCreateUserProcess | API Monitor | No CreateProcess* calls logged |
