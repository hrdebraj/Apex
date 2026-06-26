import { useCallback, useEffect, useState } from "react";
import {
  listenerService,
  type ListenerResponse,
} from "../services/listenerService";
import { apiClient } from "../services/api";
import {
  payloadService,
  type Platform,
  type OutputFormat,
  type SleepMethod,
  type EncryptionMethod,
  type SyscallMethod,
} from "../services/payloadService";
import {
  Cpu,
  Download,
  FileCode,
  Shield,
  Zap,
  Monitor,
  Terminal as TerminalIcon,
  Apple,
} from "lucide-react";

type Profile = { name: string; description: string };

const platforms: { id: Platform; label: string; icon: typeof Monitor }[] = [
  { id: "windows", label: "Windows", icon: Monitor },
  { id: "linux", label: "Linux", icon: TerminalIcon },
  { id: "macos", label: "macOS", icon: Apple },
];

const winOutputOptions: { value: OutputFormat; label: string; icon: typeof Cpu }[] = [
  { value: "exe", label: "Executable (.exe)", icon: Cpu },
  { value: "dll", label: "DLL (.dll)", icon: FileCode },
  { value: "shellcode", label: "Shellcode (.bin)", icon: Zap },
  { value: "service_exe", label: "Service EXE", icon: Cpu },
];

const linuxOutputOptions: { value: OutputFormat; label: string; icon: typeof Cpu }[] = [
  { value: "elf", label: "ELF Binary", icon: Cpu },
];

const macOutputOptions: { value: OutputFormat; label: string; icon: typeof Cpu }[] = [
  { value: "macho", label: "Mach-O Binary", icon: Cpu },
];

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <label className="flex items-center justify-between cursor-pointer group">
      <span className="text-sm text-apex-text group-hover:text-apex-accent transition-colors">
        {label}
      </span>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="rounded border-apex-border bg-apex-bg text-apex-accent focus:ring-apex-accent"
      />
    </label>
  );
}

export default function AgentBuilderPage() {
  const [listeners, setListeners] = useState<ListenerResponse[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);

  // Common
  const [platform, setPlatform] = useState<Platform>("windows");
  const [outputFormat, setOutputFormat] = useState<OutputFormat>("exe");
  const [listenerId, setListenerId] = useState("");
  const [callbackHost, setCallbackHost] = useState("");
  const [callbackPort, setCallbackPort] = useState(0);
  const [profileName, setProfileName] = useState("default");
  const [generating, setGenerating] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error" | "info";
    text: string;
  } | null>(null);

  // Windows evasion
  const [sleepObfuscation, setSleepObfuscation] = useState(true);
  const [sleepMethod, setSleepMethod] = useState<SleepMethod>("ekko");
  const [encryptedShellcode, setEncryptedShellcode] = useState(true);
  const [encryptionMethod, setEncryptionMethod] = useState<EncryptionMethod>("aes256");
  const [unhookNtdll, setUnhookNtdll] = useState(true);
  const [etwPatch, setEtwPatch] = useState(true);
  const [amsiPatch, setAmsiPatch] = useState(true);
  const [hardwareBreakpoint, setHardwareBreakpoint] = useState(false);
  const [indirectSyscall, setIndirectSyscall] = useState(true);
  const [syscallMethod, setSyscallMethod] = useState<SyscallMethod>("auto");
  const [ntProcess, setNtProcess] = useState(true);
  const [heapEncrypt, setHeapEncrypt] = useState(true);
  const [peStomp, setPeStomp] = useState(true);
  const [peStompMode, setPeStompMode] = useState(2);
  const [peStompRandomise, setPeStompRandomise] = useState(false);
  const [udrl, setUdrl] = useState(true);
  const [dripLoad, setDripLoad] = useState(true);
  const [retAddrSpoof, setRetAddrSpoof] = useState(true);
  const [syntheticFrames, setSyntheticFrames] = useState(true);
  const [blockDlls, setBlockDlls] = useState(true);
  const [argSpoof, setArgSpoof] = useState(true);
  const [ppidSpoof, setPpidSpoof] = useState(true);

  // POSIX evasion (Linux/macOS)
  const [antiDebug, setAntiDebug] = useState(true);
  const [procMask, setProcMask] = useState(true);
  const [selfDelete, setSelfDelete] = useState(false);
  const [envClean, setEnvClean] = useState(true);
  const [sandboxCheck, setSandboxCheck] = useState(true);

  const handlePlatformChange = (p: Platform) => {
    setPlatform(p);
    if (p === "windows") setOutputFormat("exe");
    else if (p === "linux") setOutputFormat("elf");
    else setOutputFormat("macho");
  };

  const fetchListeners = useCallback(async () => {
    try {
      const data = await listenerService.list();
      setListeners(data);
      if (data.length > 0 && !listenerId) setListenerId(data[0].id);
    } catch {
      setListeners([]);
    }
  }, [listenerId]);

  const fetchProfiles = useCallback(async () => {
    try {
      const data = await apiClient.get<Profile[]>("/api/profiles");
      setProfiles(data);
      if (data.length > 0 && !profileName) setProfileName(data[0].name);
    } catch {
      setProfiles([{ name: "default", description: "Default profile" }]);
    }
  }, [profileName]);

  useEffect(() => {
    fetchListeners();
    fetchProfiles();
  }, [fetchListeners, fetchProfiles]);

  const handleGenerate = async () => {
    if (!listenerId) {
      setMessage({ type: "error", text: "Select a listener" });
      return;
    }
    setGenerating(true);
    setMessage(null);
    try {
      const res = await payloadService.generate({
        platform,
        output_format: outputFormat,
        listener_id: listenerId,
        callback_host: callbackHost || undefined,
        callback_port: callbackPort || undefined,
        profile_name: profileName,
        sleep_obfuscation: sleepObfuscation,
        sleep_method: sleepMethod,
        encrypted_shellcode: encryptedShellcode,
        encryption_method: encryptionMethod,
        unhook_ntdll: unhookNtdll,
        etw_patch: etwPatch,
        amsi_patch: amsiPatch,
        hardware_breakpoint: hardwareBreakpoint,
        indirect_syscall: indirectSyscall,
        syscall_method: syscallMethod,
        nt_process: ntProcess,
        heap_encrypt: heapEncrypt,
        pe_stomp: peStomp,
        pe_stomp_mode: peStompMode,
        pe_stomp_randomise: peStompRandomise,
        udrl,
        drip_load: dripLoad,
        ret_addr_spoof: retAddrSpoof,
        synthetic_frames: syntheticFrames,
        block_dlls: blockDlls,
        arg_spoof: argSpoof,
        ppid_spoof: ppidSpoof,
        anti_debug: antiDebug,
        proc_mask: procMask,
        self_delete: selfDelete,
        env_clean: envClean,
        sandbox_check: sandboxCheck,
      });
      setMessage({
        type: res.success ? "success" : "info",
        text: res.message,
      });
      if (res.success && res.payload_base64 && res.filename) {
        const bin = Uint8Array.from(atob(res.payload_base64), (c) =>
          c.charCodeAt(0)
        );
        const blob = new Blob([bin], { type: "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = res.filename;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (err) {
      setMessage({
        type: "error",
        text: err instanceof Error ? err.message : "Generation failed",
      });
    } finally {
      setGenerating(false);
    }
  };

  const currentOutputOptions =
    platform === "windows"
      ? winOutputOptions
      : platform === "linux"
        ? linuxOutputOptions
        : macOutputOptions;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-apex-text">Agent Builder</h2>
        <p className="text-sm text-apex-muted mt-0.5">
          Generate payloads for Windows, Linux, or macOS. Configure callback and
          evasion options per platform.
        </p>
      </div>

      {/* Platform Tabs */}
      <div className="flex gap-1 bg-apex-bg rounded-lg p-1 border border-apex-border">
        {platforms.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => handlePlatformChange(id)}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-md text-sm font-medium transition-all ${platform === id
              ? "bg-apex-accent/20 text-apex-accent border border-apex-accent/40 shadow-sm"
              : "text-apex-muted hover:text-apex-text hover:bg-apex-surface"
              }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Output & Listener — full width row */}
      <div className="apex-card p-5 space-y-4">
        <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
          <Download className="w-4 h-4 text-apex-accent" />
          Output & Listener
        </h3>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Left: format + listener */}
          <div className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
                Output Format
              </label>
              <div className="grid grid-cols-2 gap-2">
                {currentOutputOptions.map(({ value, label, icon: Icon }) => (
                  <button
                    key={value}
                    onClick={() => setOutputFormat(value)}
                    className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-mono transition-colors ${outputFormat === value
                      ? "bg-apex-accent/20 text-apex-accent border border-apex-accent/40"
                      : "bg-apex-bg border border-apex-border text-apex-muted hover:text-apex-text"
                      }`}
                  >
                    <Icon className="w-4 h-4" />
                    {label}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
                Listener
              </label>
              <select
                value={listenerId}
                onChange={(e) => setListenerId(e.target.value)}
                className="apex-select w-full"
                style={{ colorScheme: "dark" }}
              >
                <option value="">Select listener</option>
                {listeners.map((l) => (
                  <option
                    key={l.id}
                    value={l.id}
                    className="bg-apex-surface text-apex-text"
                  >
                    {l.name} ({l.protocol} {l.bind_address}:{l.bind_port})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Right: host, port, profile */}
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
                  Callback Host
                </label>
                <input
                  type="text"
                  value={callbackHost}
                  onChange={(e) => setCallbackHost(e.target.value)}
                  placeholder="Override (e.g. your IP)"
                  className="apex-input text-sm"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
                  Callback Port
                </label>
                <input
                  type="number"
                  value={callbackPort || ""}
                  onChange={(e) =>
                    setCallbackPort(parseInt(e.target.value, 10) || 0)
                  }
                  placeholder="Override"
                  className="apex-input text-sm"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
                Malleable Profile
              </label>
              <select
                value={profileName}
                onChange={(e) => setProfileName(e.target.value)}
                className="apex-select w-full"
                style={{ colorScheme: "dark" }}
              >
                {profiles.map((p) => (
                  <option
                    key={p.name}
                    value={p.name}
                    className="bg-apex-surface text-apex-text"
                  >
                    {p.name}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* OPSEC Options — platform-specific, two-column for Windows */}
      {platform === "windows" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Left OPSEC column */}
          <div className="apex-card p-5 space-y-4">
            <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4 text-apex-accent" />
              Evasion — Sleep & Crypto
            </h3>

            <div className="space-y-3">
              <Toggle
                label="Sleep Obfuscation (Ekko/Foliage)"
                checked={sleepObfuscation}
                onChange={setSleepObfuscation}
              />
              {sleepObfuscation && (
                <select
                  value={sleepMethod}
                  onChange={(e) =>
                    setSleepMethod(e.target.value as SleepMethod)
                  }
                  className="apex-select text-sm"
                  style={{ colorScheme: "dark" }}
                >
                  <option value="ekko" className="bg-apex-surface text-apex-text">
                    Ekko
                  </option>
                  <option value="foliage" className="bg-apex-surface text-apex-text">
                    Foliage
                  </option>
                </select>
              )}

              <Toggle
                label="Encrypted Shellcode (AES-256/ChaCha20)"
                checked={encryptedShellcode}
                onChange={setEncryptedShellcode}
              />
              {encryptedShellcode && (
                <select
                  value={encryptionMethod}
                  onChange={(e) =>
                    setEncryptionMethod(e.target.value as EncryptionMethod)
                  }
                  className="apex-select text-sm"
                  style={{ colorScheme: "dark" }}
                >
                  <option value="aes256" className="bg-apex-surface text-apex-text">
                    AES-256
                  </option>
                  <option value="chacha20" className="bg-apex-surface text-apex-text">
                    ChaCha20
                  </option>
                </select>
              )}

              <Toggle label="Unhook ntdll (EDR evasion)" checked={unhookNtdll} onChange={setUnhookNtdll} />
              <Toggle label="ETW Patching" checked={etwPatch} onChange={setEtwPatch} />
              <Toggle label="AMSI Patching" checked={amsiPatch} onChange={setAmsiPatch} />
              <Toggle label="Hardware Breakpoint (DR0-DR3)" checked={hardwareBreakpoint} onChange={setHardwareBreakpoint} />

              <Toggle
                label="Heap Encryption During Sleep"
                checked={heapEncrypt}
                onChange={setHeapEncrypt}
              />
            </div>

            {/* Indirect Syscalls */}
            <div className="pt-1 border-t border-apex-border/50 space-y-3">
              <Toggle
                label="Indirect Syscalls (HellsGate / HalosGate)"
                checked={indirectSyscall}
                onChange={setIndirectSyscall}
              />
              {indirectSyscall && (
                <div className="space-y-2">
                  <select
                    value={syscallMethod}
                    onChange={(e) => setSyscallMethod(e.target.value as SyscallMethod)}
                    className="apex-select text-sm w-full"
                    style={{ colorScheme: "dark" }}
                  >
                    <option value="auto" className="bg-apex-surface text-apex-text">
                      Auto — HalosGate scan + HellsGate fallback
                    </option>
                    <option value="hellsgate" className="bg-apex-surface text-apex-text">
                      HellsGate — On-disk ntdll SSN read
                    </option>
                    <option value="halosgate" className="bg-apex-surface text-apex-text">
                      HalosGate — In-memory neighbor scan
                    </option>
                  </select>
                </div>
              )}

              <Toggle
                label="NtCreateUserProcess (No ETW exec events)"
                checked={ntProcess}
                onChange={setNtProcess}
              />
            </div>
          </div>

          {/* Right OPSEC column */}
          <div className="apex-card p-5 space-y-4">
            <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4 text-apex-accent" />
              Evasion — Memory & Process
            </h3>

            {/* PE Header Stomping */}
            <div className="space-y-3">
              <Toggle
                label="PE Header Stomping (defeats pe-sieve)"
                checked={peStomp}
                onChange={setPeStomp}
              />
              {peStomp && (
                <div className="space-y-2">
                  <div>
                    <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
                      Stomp Depth
                    </label>
                    <div className="grid grid-cols-3 gap-1.5">
                      {[
                        { v: 1, label: "DOS-only",     desc: "MZ + 64 B" },
                        { v: 2, label: "Full NT",      desc: "Recommended" },
                        { v: 3, label: "Sledgehammer", desc: "Entire page" },
                      ].map(({ v, label, desc }) => (
                        <button
                          key={v}
                          onClick={() => setPeStompMode(v)}
                          className={`flex flex-col items-center px-2 py-2 rounded-md text-xs font-medium transition-colors ${
                            peStompMode === v
                              ? "bg-apex-accent/20 text-apex-accent border border-apex-accent/40"
                              : "bg-apex-bg border border-apex-border text-apex-muted hover:text-apex-text"
                          }`}
                        >
                          <span>{label}</span>
                          <span className="text-[10px] opacity-60 mt-0.5">{desc}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                  <Toggle
                    label="Pseudo-random fill (vs zero-fill)"
                    checked={peStompRandomise}
                    onChange={setPeStompRandomise}
                  />
                </div>
              )}
            </div>

            {/* Memory Evasion */}
            <div className="pt-1 border-t border-apex-border/50 space-y-3">
              <Toggle label="User-Defined Reflective Loader (UDRL)" checked={udrl} onChange={setUdrl} />
              <Toggle label="Drip-Loading (Gradual Alloc)" checked={dripLoad} onChange={setDripLoad} />
            </div>

            {/* Call Stack Evasion */}
            <div className="pt-1 border-t border-apex-border/50 space-y-3">
              <Toggle label="Return Address Spoofing" checked={retAddrSpoof} onChange={setRetAddrSpoof} />
              <Toggle label="Synthetic Stack Frames" checked={syntheticFrames} onChange={setSyntheticFrames} />
            </div>

            {/* Process Execution Evasion */}
            <div className="pt-1 border-t border-apex-border/50 space-y-3">
              <Toggle label="BlockDLLs (Block Non-Microsoft DLLs)" checked={blockDlls} onChange={setBlockDlls} />
              <Toggle label="Process Argument Spoofing" checked={argSpoof} onChange={setArgSpoof} />
              <Toggle label="PPID Spoofing (explorer.exe parent)" checked={ppidSpoof} onChange={setPpidSpoof} />
              {ppidSpoof && (
                <div className="p-2.5 rounded-md bg-apex-bg border border-apex-border text-xs text-apex-muted leading-relaxed">
                  <span className="text-apex-accent font-medium">PPID Spoofing</span>: Child processes
                  are spawned under <code className="text-apex-accent">explorer.exe</code> as
                  the apparent parent. Defeats EDR parent-child chain analysis that flags
                  anomalous process trees (e.g. agent.exe → cmd.exe).
                  Runtime toggle: <code className="text-apex-accent">ppidspoof on/off</code>.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {platform === "linux" && (
        <div className="apex-card p-5 space-y-4">
          <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-apex-accent" />
            Linux OPSEC
          </h3>
          <div className="space-y-3">
            <Toggle label="Anti-Debug (ptrace TRACEME + TracerPid)" checked={antiDebug} onChange={setAntiDebug} />
            <Toggle label="Process Name Masking (prctl + argv)" checked={procMask} onChange={setProcMask} />
            <Toggle label="Self-Delete Binary After Launch" checked={selfDelete} onChange={setSelfDelete} />
            <Toggle label="LD_PRELOAD / LD_AUDIT Cleanup" checked={envClean} onChange={setEnvClean} />
            <Toggle label="Sandbox / VM Detection" checked={sandboxCheck} onChange={setSandboxCheck} />
            <div className="mt-3 p-3 rounded-md bg-apex-bg border border-apex-border">
              <p className="text-xs text-apex-muted leading-relaxed">
                <span className="text-apex-accent font-medium">Linux agent</span>{" "}
                uses raw TCP sockets for HTTP beaconing. Runs as a daemon by
                default. Supports all standard commands: shell, whoami, ps, cd,
                pwd, download, sleep, exit. Agent masks itself as{" "}
                <code className="text-apex-accent">[kworker/u:0]</code> in
                process listings.
              </p>
            </div>
          </div>
        </div>
      )}

      {platform === "macos" && (
        <div className="apex-card p-5 space-y-4">
          <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-apex-accent" />
            macOS OPSEC
          </h3>
          <div className="space-y-3">
            <Toggle label="Anti-Debug (PT_DENY_ATTACH + sysctl)" checked={antiDebug} onChange={setAntiDebug} />
            <Toggle label="Process Name Masking (argv overwrite)" checked={procMask} onChange={setProcMask} />
            <Toggle label="Self-Delete Binary After Launch" checked={selfDelete} onChange={setSelfDelete} />
            <Toggle label="DYLD Environment Cleanup" checked={envClean} onChange={setEnvClean} />
            <Toggle label="Sandbox / VM Detection" checked={sandboxCheck} onChange={setSandboxCheck} />
            <div className="mt-3 p-3 rounded-md bg-apex-bg border border-apex-border">
              <p className="text-xs text-apex-muted leading-relaxed">
                <span className="text-apex-accent font-medium">macOS agent</span>{" "}
                uses raw TCP sockets for HTTP beaconing. Daemonizes by default.
                Supports all standard commands. Uses PT_DENY_ATTACH to block
                debuggers and cleans DYLD_INSERT_LIBRARIES to prevent monitoring
                shim injection.
                {" "}
                <span className="text-apex-warning">
                  Cross-compilation requires osxcross toolchain.
                </span>
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Generate & Message */}
      <div className="flex items-center justify-between gap-4">
        <button
          onClick={handleGenerate}
          disabled={generating || !listenerId}
          className="apex-btn apex-btn-primary flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {generating ? (
            <span className="animate-pulse">Generating…</span>
          ) : (
            <>
              <Download className="w-4 h-4" />
              Generate{" "}
              {platform === "windows"
                ? "Windows"
                : platform === "linux"
                  ? "Linux"
                  : "macOS"}{" "}
              Payload
            </>
          )}
        </button>
        {message && (
          <div
            className={`flex-1 px-4 py-2 rounded-md text-sm ${message.type === "success"
              ? "bg-apex-accent/10 text-apex-accent"
              : message.type === "error"
                ? "bg-apex-danger/10 text-apex-danger"
                : "bg-apex-muted/10 text-apex-muted"
              }`}
          >
            {message.text}
          </div>
        )}
      </div>
    </div>
  );
}
