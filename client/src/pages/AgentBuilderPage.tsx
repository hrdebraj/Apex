import { useCallback, useEffect, useState } from "react";
import {
  listenerService,
  type ListenerResponse,
} from "../services/listenerService";
import { apiClient } from "../services/api";
import {
  payloadService,
  type OutputFormat,
  type SleepMethod,
  type EncryptionMethod,
} from "../services/payloadService";
import {
  Cpu,
  Download,
  FileCode,
  Shield,
  Zap,
} from "lucide-react";

type Profile = { name: string; description: string };

export default function AgentBuilderPage() {
  const [listeners, setListeners] = useState<ListenerResponse[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [outputFormat, setOutputFormat] = useState<OutputFormat>("exe");
  const [listenerId, setListenerId] = useState("");
  const [callbackHost, setCallbackHost] = useState("");
  const [callbackPort, setCallbackPort] = useState(0);
  const [profileName, setProfileName] = useState("default");
  const [sleepObfuscation, setSleepObfuscation] = useState(true);
  const [sleepMethod, setSleepMethod] = useState<SleepMethod>("ekko");
  const [encryptedShellcode, setEncryptedShellcode] = useState(true);
  const [encryptionMethod, setEncryptionMethod] =
    useState<EncryptionMethod>("aes256");
  const [unhookNtdll, setUnhookNtdll] = useState(true);
  const [etwPatch, setEtwPatch] = useState(true);
  const [amsiPatch, setAmsiPatch] = useState(true);
  const [hardwareBreakpoint, setHardwareBreakpoint] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [message, setMessage] = useState<{
    type: "success" | "error" | "info";
    text: string;
  } | null>(null);
  const fetchListeners = useCallback(async () => {
    try {
      const data = await listenerService.list();
      setListeners(data);
      if (data.length > 0 && !listenerId) {
        setListenerId(data[0].id);
      }
    } catch {
      setListeners([]);
    }
  }, [listenerId]);

  const fetchProfiles = useCallback(async () => {
    try {
      const data = await apiClient.get<Profile[]>("/api/profiles");
      setProfiles(data);
      if (data.length > 0 && !profileName) {
        setProfileName(data[0].name);
      }
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
      });
      setMessage({
        type: res.success ? "success" : "info",
        text: res.message,
      });
      if (res.success && res.payload_base64 && res.filename) {
        const bin = Uint8Array.from(atob(res.payload_base64), (c) => c.charCodeAt(0));
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

  const outputOptions: { value: OutputFormat; label: string; icon: typeof Cpu }[] = [
    { value: "exe", label: "Executable (.exe)", icon: Cpu },
    { value: "dll", label: "DLL (.dll)", icon: FileCode },
    { value: "shellcode", label: "Shellcode (.bin)", icon: Zap },
    { value: "service_exe", label: "Service EXE", icon: Cpu },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-apex-text">
          Agent Builder
        </h2>
        <p className="text-sm text-apex-muted mt-0.5">
          Generate EXE, DLL, or shellcode payloads. Configure callback and evasion options.
        </p>
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
              {outputOptions.map(({ value, label, icon: Icon }) => (
                <button
                  key={value}
                  onClick={() => setOutputFormat(value)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-md text-sm font-mono transition-colors ${
                    outputFormat === value
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
                onChange={(e) => setCallbackPort(parseInt(e.target.value, 10) || 0)}
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

        {/* OPSEC Options */}
        <div className="apex-card p-5 space-y-4">
          <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
            <Shield className="w-4 h-4 text-apex-accent" />
            OPSEC Options
          </h3>

          <div className="space-y-3">
            <label className="flex items-center justify-between cursor-pointer group">
              <span className="text-sm text-apex-text group-hover:text-apex-accent transition-colors">
                Sleep Obfuscation (Ekko/Foliage)
              </span>
              <input
                type="checkbox"
                checked={sleepObfuscation}
                onChange={(e) => setSleepObfuscation(e.target.checked)}
                className="rounded border-apex-border bg-apex-bg text-apex-accent focus:ring-apex-accent"
              />
            </label>
            {sleepObfuscation && (
              <select
                value={sleepMethod}
                onChange={(e) => setSleepMethod(e.target.value as SleepMethod)}
                className="apex-select text-sm"
                style={{ colorScheme: "dark" }}
              >
                <option value="ekko" className="bg-apex-surface text-apex-text">Ekko</option>
                <option value="foliage" className="bg-apex-surface text-apex-text">Foliage</option>
              </select>
            )}

            <label className="flex items-center justify-between cursor-pointer group">
              <span className="text-sm text-apex-text group-hover:text-apex-accent transition-colors">
                Encrypted Shellcode (AES-256/ChaCha20)
              </span>
              <input
                type="checkbox"
                checked={encryptedShellcode}
                onChange={(e) => setEncryptedShellcode(e.target.checked)}
                className="rounded border-apex-border bg-apex-bg text-apex-accent focus:ring-apex-accent"
              />
            </label>
            {encryptedShellcode && (
              <select
                value={encryptionMethod}
                onChange={(e) => setEncryptionMethod(e.target.value as EncryptionMethod)}
                className="apex-select text-sm"
                style={{ colorScheme: "dark" }}
              >
                <option value="aes256" className="bg-apex-surface text-apex-text">AES-256</option>
                <option value="chacha20" className="bg-apex-surface text-apex-text">ChaCha20</option>
              </select>
            )}

            <label className="flex items-center justify-between cursor-pointer group">
              <span className="text-sm text-apex-text group-hover:text-apex-accent transition-colors">
                Unhook ntdll (EDR evasion)
              </span>
              <input
                type="checkbox"
                checked={unhookNtdll}
                onChange={(e) => setUnhookNtdll(e.target.checked)}
                className="rounded border-apex-border bg-apex-bg text-apex-accent focus:ring-apex-accent"
              />
            </label>

            <label className="flex items-center justify-between cursor-pointer group">
              <span className="text-sm text-apex-text group-hover:text-apex-accent transition-colors">
                ETW Patching
              </span>
              <input
                type="checkbox"
                checked={etwPatch}
                onChange={(e) => setEtwPatch(e.target.checked)}
                className="rounded border-apex-border bg-apex-bg text-apex-accent focus:ring-apex-accent"
              />
            </label>

            <label className="flex items-center justify-between cursor-pointer group">
              <span className="text-sm text-apex-text group-hover:text-apex-accent transition-colors">
                AMSI Patching
              </span>
              <input
                type="checkbox"
                checked={amsiPatch}
                onChange={(e) => setAmsiPatch(e.target.checked)}
                className="rounded border-apex-border bg-apex-bg text-apex-accent focus:ring-apex-accent"
              />
            </label>

            <label className="flex items-center justify-between cursor-pointer group">
              <span className="text-sm text-apex-text group-hover:text-apex-accent transition-colors">
                Hardware Breakpoint (DR0-DR3)
              </span>
              <input
                type="checkbox"
                checked={hardwareBreakpoint}
                onChange={(e) => setHardwareBreakpoint(e.target.checked)}
                className="rounded border-apex-border bg-apex-bg text-apex-accent focus:ring-apex-accent"
              />
            </label>
          </div>
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
            <>
              <span className="animate-pulse">Generating…</span>
            </>
          ) : (
            <>
              <Download className="w-4 h-4" />
              Generate Payload
            </>
          )}
        </button>
        {message && (
          <div
            className={`flex-1 px-4 py-2 rounded-md text-sm ${
              message.type === "success"
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
