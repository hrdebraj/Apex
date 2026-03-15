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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Output & Listener */}
        <div className="apex-card p-5 space-y-4">
          <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
            <Download className="w-4 h-4 text-apex-accent" />
            Output & Listener
          </h3>

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

        {/* OPSEC Options — platform-specific */}
        <div className="apex-card p-5 space-y-4">
          <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-apex-accent" />
            {platform === "windows"
              ? "Windows OPSEC"
              : platform === "linux"
                ? "Linux OPSEC"
                : "macOS OPSEC"}
          </h3>

          {platform === "windows" && (
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
                  <option
                    value="ekko"
                    className="bg-apex-surface text-apex-text"
                  >
                    Ekko
                  </option>
                  <option
                    value="foliage"
                    className="bg-apex-surface text-apex-text"
                  >
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
                  <option
                    value="aes256"
                    className="bg-apex-surface text-apex-text"
                  >
                    AES-256
                  </option>
                  <option
                    value="chacha20"
                    className="bg-apex-surface text-apex-text"
                  >
                    ChaCha20
                  </option>
                </select>
              )}

              <Toggle
                label="Unhook ntdll (EDR evasion)"
                checked={unhookNtdll}
                onChange={setUnhookNtdll}
              />
              <Toggle
                label="ETW Patching"
                checked={etwPatch}
                onChange={setEtwPatch}
              />
              <Toggle
                label="AMSI Patching"
                checked={amsiPatch}
                onChange={setAmsiPatch}
              />
              <Toggle
                label="Hardware Breakpoint (DR0-DR3)"
                checked={hardwareBreakpoint}
                onChange={setHardwareBreakpoint}
              />

              {/* ── Indirect Syscalls ── */}
              <div className="pt-1 border-t border-apex-border/50">
                <Toggle
                  label="Indirect Syscalls (HellsGate / HalosGate)"
                  checked={indirectSyscall}
                  onChange={setIndirectSyscall}
                />
                {indirectSyscall && (
                  <div className="mt-2 space-y-2">
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
                    <div className="p-2.5 rounded-md bg-apex-bg border border-apex-border text-xs text-apex-muted leading-relaxed">
                      {syscallMethod === "auto" && (
                        <span>
                          <span className="text-apex-accent font-medium">Auto</span>: reads SSNs
                          from clean on-disk ntdll first. If any function is hooked,
                          scans ±32 neighbour stubs by address to derive the correct
                          SSN. Syscall executes from our own RWX stub — not ntdll —
                          defeating call-stack EDR heuristics.
                        </span>
                      )}
                      {syscallMethod === "hellsgate" && (
                        <span>
                          <span className="text-apex-accent font-medium">HellsGate</span>: maps
                          ntdll.dll from disk as a clean reference and reads SSNs by
                          sorting exports by address (index = SSN). Bypasses all
                          user-mode hooks regardless of what the in-memory copy looks
                          like. Best when disk I/O isn’t monitored.
                        </span>
                      )}
                      {syscallMethod === "halosgate" && (
                        <span>
                          <span className="text-apex-accent font-medium">HalosGate</span>: reads
                          SSNs directly from in-memory ntdll stubs. If a stub is
                          hooked, walks forward and backward through neighbours in
                          export-table address order to find the nearest clean stub
                          and derives the target SSN by ±offset. Works even if disk
                          access is restricted or monitored by EDR.
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {platform === "linux" && (
            <div className="space-y-3">
              <Toggle
                label="Anti-Debug (ptrace TRACEME + TracerPid)"
                checked={antiDebug}
                onChange={setAntiDebug}
              />
              <Toggle
                label="Process Name Masking (prctl + argv)"
                checked={procMask}
                onChange={setProcMask}
              />
              <Toggle
                label="Self-Delete Binary After Launch"
                checked={selfDelete}
                onChange={setSelfDelete}
              />
              <Toggle
                label="LD_PRELOAD / LD_AUDIT Cleanup"
                checked={envClean}
                onChange={setEnvClean}
              />
              <Toggle
                label="Sandbox / VM Detection"
                checked={sandboxCheck}
                onChange={setSandboxCheck}
              />

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
          )}

          {platform === "macos" && (
            <div className="space-y-3">
              <Toggle
                label="Anti-Debug (PT_DENY_ATTACH + sysctl)"
                checked={antiDebug}
                onChange={setAntiDebug}
              />
              <Toggle
                label="Process Name Masking (argv overwrite)"
                checked={procMask}
                onChange={setProcMask}
              />
              <Toggle
                label="Self-Delete Binary After Launch"
                checked={selfDelete}
                onChange={setSelfDelete}
              />
              <Toggle
                label="DYLD Environment Cleanup"
                checked={envClean}
                onChange={setEnvClean}
              />
              <Toggle
                label="Sandbox / VM Detection"
                checked={sandboxCheck}
                onChange={setSandboxCheck}
              />

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
          )}
        </div>
      </div>

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
