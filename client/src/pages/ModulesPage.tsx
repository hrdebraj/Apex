import { useCallback, useEffect, useState } from "react";
import { payloadService } from "../services/payloadService";
import { apiClient } from "../services/api";
import {
  FileCode,
  Upload,
  Shield,
  HardDrive,
  Trash2,
  RefreshCw,
  FileText,
  Key,
  Eye,
  Bug,
  Fingerprint,
  Zap,
  Cpu,
  Activity,
  Lock,
  FileX2,
  Terminal,
} from "lucide-react";

interface BOFFile {
  id: string;
  name: string;
  size?: number;
  hash?: string;
  uploaded_at?: string;
}

interface ProfileInfo {
  name: string;
  description: string;
  sleep: number;
  jitter: number;
  get_uris: string[];
  post_uris: string[];
  user_agents: string[];
}

const sampleBOFs = [
  {
    name: "whoami.o",
    desc: "Returns current user, domain, and privilege info via Windows API (no cmd.exe spawn)",
    mitre: "T1033",
  },
  {
    name: "netstat.o",
    desc: "Lists active TCP/UDP connections and listening ports without spawning netstat.exe",
    mitre: "T1049",
  },
  {
    name: "dir_list.o",
    desc: "Enumerates directory contents using FindFirstFile/FindNextFile (no cmd.exe)",
    mitre: "T1083",
  },
  {
    name: "reg_query.o",
    desc: "Queries Windows registry keys and values via RegOpenKeyEx/RegQueryValueEx",
    mitre: "T1012",
  },
  {
    name: "env_vars.o",
    desc: "Dumps all environment variables from the current process context",
    mitre: "T1082",
  },
  {
    name: "arp_table.o",
    desc: "Reads ARP cache via GetIpNetTable without spawning arp.exe",
    mitre: "T1016",
  },
];

export default function ModulesPage() {
  const [bofFiles, setBofFiles] = useState<BOFFile[]>([]);
  const [bofUploading, setBofUploading] = useState(false);
  const [bofMessage, setBofMessage] = useState<string | null>(null);
  const [profiles, setProfiles] = useState<ProfileInfo[]>([]);
  const [profileUploading, setProfileUploading] = useState(false);
  const [profileMessage, setProfileMessage] = useState<string | null>(null);
  const [byovdEnabled, setByovdEnabled] = useState(false);
  const [byovdDriverPath, setByovdDriverPath] = useState("");
  const [activeTab, setActiveTab] = useState<"bof" | "profiles" | "evasion">("bof");

  const fetchBOFs = useCallback(async () => {
    try {
      const data = await payloadService.listBOFs();
      setBofFiles(Array.isArray(data) ? data : []);
    } catch {
      setBofFiles([]);
    }
  }, []);

  const fetchProfiles = useCallback(async () => {
    try {
      const data = await apiClient.get<ProfileInfo[]>("/api/profiles");
      setProfiles(Array.isArray(data) ? data : []);
    } catch {
      setProfiles([]);
    }
  }, []);

  useEffect(() => {
    fetchBOFs();
    fetchProfiles();
  }, [fetchBOFs, fetchProfiles]);

  const handleBOFUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setBofUploading(true);
    setBofMessage(null);
    try {
      await payloadService.uploadBOF(file);
      setBofMessage(`Uploaded: ${file.name}`);
      fetchBOFs();
    } catch (err) {
      setBofMessage(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setBofUploading(false);
      e.target.value = "";
    }
  };

  const handleDeleteBOF = async (id: string, name: string) => {
    try {
      await payloadService.deleteBOF(id);
      setBofMessage(`Deleted: ${name}`);
      fetchBOFs();
    } catch (err) {
      setBofMessage(err instanceof Error ? err.message : "Delete failed");
    }
  };

  const handleProfileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setProfileUploading(true);
    setProfileMessage(null);
    try {
      const formData = new FormData();
      formData.append("profile", file);
      await apiClient.postForm<ProfileInfo>("/api/profiles", formData);
      setProfileMessage(`Uploaded: ${file.name}`);
      fetchProfiles();
    } catch (err) {
      setProfileMessage(err instanceof Error ? err.message : "Upload failed");
    } finally {
      setProfileUploading(false);
      e.target.value = "";
    }
  };

  const handleDeleteProfile = async (name: string) => {
    try {
      await apiClient.delete<{ status: string }>(`/api/profiles/${name}`);
      setProfileMessage(`Deleted: ${name}`);
      fetchProfiles();
    } catch (err) {
      setProfileMessage(err instanceof Error ? err.message : "Delete failed");
    }
  };

  const formatSize = (bytes?: number) => {
    if (!bytes) return "--";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const tabs = [
    { id: "bof" as const, label: "BOF & Modules", icon: FileCode },
    { id: "profiles" as const, label: "Malleable Profiles", icon: FileText },
    { id: "evasion" as const, label: "Evasion & Capabilities", icon: Shield },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-apex-text">Modules</h2>
        <p className="text-sm text-apex-muted mt-0.5">
          Manage BOFs, malleable C2 profiles, and review evasion capabilities.
        </p>
      </div>

      {/* Tab Bar */}
      <div className="flex gap-1 bg-apex-bg rounded-lg p-1 border border-apex-border">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
              activeTab === id
                ? "bg-apex-accent/20 text-apex-accent border border-apex-accent/40"
                : "text-apex-muted hover:text-apex-text hover:bg-apex-surface"
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* BOF Tab */}
      {activeTab === "bof" && (
        <div className="space-y-6">
          <div className="apex-card p-5 space-y-4 card-hover">
            <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
              <FileCode className="w-4 h-4 text-apex-accent" />
              Beacon Object Files (BOF)
            </h3>
            <p className="text-xs text-apex-muted">
              Upload COFF/BOF .o or .obj files. Execute from Terminal with: <code className="text-apex-accent">bof &lt;name&gt; [args]</code>
            </p>
            <div className="flex items-center gap-3">
              <label className="apex-btn apex-btn-ghost cursor-pointer flex items-center gap-2">
                <Upload className="w-4 h-4" />
                {bofUploading ? "Uploading..." : "Upload BOF"}
                <input
                  type="file"
                  accept=".o,.obj"
                  onChange={handleBOFUpload}
                  disabled={bofUploading}
                  className="hidden"
                />
              </label>
              <button onClick={fetchBOFs} className="apex-btn apex-btn-ghost text-sm flex items-center gap-1">
                <RefreshCw className="w-3.5 h-3.5" />
                Refresh
              </button>
            </div>
            {bofMessage && (
              <div className="text-sm text-apex-accent">{bofMessage}</div>
            )}

            {bofFiles.length > 0 ? (
              <div className="border border-apex-border rounded-md overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-apex-bg/50 text-apex-muted text-xs uppercase tracking-wider">
                      <th className="text-left px-3 py-2">Name</th>
                      <th className="text-left px-3 py-2">Size</th>
                      <th className="text-left px-3 py-2">Hash</th>
                      <th className="text-left px-3 py-2">Uploaded</th>
                      <th className="text-right px-3 py-2"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {bofFiles.map((b) => (
                      <tr key={b.id} className="border-t border-apex-border hover:bg-apex-surface/50 transition-colors">
                        <td className="px-3 py-2 font-mono text-apex-text">{b.name}</td>
                        <td className="px-3 py-2 text-apex-muted">{formatSize(b.size)}</td>
                        <td className="px-3 py-2 text-apex-muted font-mono text-xs">{b.hash || "--"}</td>
                        <td className="px-3 py-2 text-apex-muted text-xs">
                          {b.uploaded_at ? new Date(b.uploaded_at).toLocaleString() : "--"}
                        </td>
                        <td className="px-3 py-2 text-right">
                          <button
                            onClick={() => handleDeleteBOF(b.id, b.name)}
                            className="text-apex-muted hover:text-apex-danger transition-colors"
                            title="Delete BOF"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="text-sm text-apex-muted/60 italic">No BOFs uploaded yet.</div>
            )}
          </div>

          {/* Sample BOFs Reference */}
          <div className="apex-card p-5 space-y-4 card-hover">
            <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
              <Zap className="w-4 h-4 text-apex-accent" />
              Available BOF Templates
            </h3>
            <p className="text-xs text-apex-muted">
              Compile these BOF source files with MinGW:{" "}
              <code className="text-apex-accent">x86_64-w64-mingw32-gcc -c -o bof.o bof.c</code>
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {sampleBOFs.map((bof) => (
                <div key={bof.name} className="bg-apex-bg/50 rounded-md p-3 border border-apex-border hover:border-apex-accent/20 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-apex-accent font-mono text-sm">{bof.name}</span>
                    <span className="text-[10px] font-mono text-apex-muted bg-apex-bg px-1.5 py-0.5 rounded">{bof.mitre}</span>
                  </div>
                  <p className="text-xs text-apex-muted">{bof.desc}</p>
                </div>
              ))}
            </div>
          </div>

          {/* BYOVD */}
          <div className="apex-card p-5 space-y-4 card-hover">
            <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
              <HardDrive className="w-4 h-4 text-apex-accent" />
              BYOVD (Bring Your Own Vulnerable Driver)
            </h3>
            <p className="text-xs text-apex-muted">
              Load a known vulnerable signed driver to blind EDR at kernel level.
            </p>
            <label className="flex items-center justify-between cursor-pointer group">
              <span className="text-sm text-apex-text group-hover:text-apex-accent transition-colors">
                Enable BYOVD
              </span>
              <input
                type="checkbox"
                checked={byovdEnabled}
                onChange={(e) => setByovdEnabled(e.target.checked)}
                className="rounded border-apex-border bg-apex-bg text-apex-accent focus:ring-apex-accent"
              />
            </label>
            {byovdEnabled && (
              <div>
                <label className="block text-xs font-medium text-apex-muted mb-1">
                  Driver path (on target)
                </label>
                <input
                  type="text"
                  value={byovdDriverPath}
                  onChange={(e) => setByovdDriverPath(e.target.value)}
                  placeholder="C:\path\to\vulnerable.sys"
                  className="apex-input text-sm"
                />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Profiles Tab */}
      {activeTab === "profiles" && (
        <div className="space-y-6">
          <div className="apex-card p-5 space-y-4 card-hover">
            <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
              <FileText className="w-4 h-4 text-apex-accent" />
              Malleable C2 Profiles
            </h3>
            <p className="text-xs text-apex-muted">
              Upload YAML profile files to shape agent HTTP traffic. Profiles control URIs, headers, user agents,
              and sleep intervals to mimic legitimate services.
            </p>
            <div className="flex items-center gap-3">
              <label className="apex-btn apex-btn-ghost cursor-pointer flex items-center gap-2">
                <Upload className="w-4 h-4" />
                {profileUploading ? "Uploading..." : "Upload Profile"}
                <input
                  type="file"
                  accept=".yaml,.yml"
                  onChange={handleProfileUpload}
                  disabled={profileUploading}
                  className="hidden"
                />
              </label>
              <button onClick={fetchProfiles} className="apex-btn apex-btn-ghost text-sm flex items-center gap-1">
                <RefreshCw className="w-3.5 h-3.5" />
                Refresh
              </button>
            </div>
            {profileMessage && (
              <div className="text-sm text-apex-accent">{profileMessage}</div>
            )}

            {profiles.length > 0 ? (
              <div className="space-y-3">
                {profiles.map((p) => (
                  <div key={p.name} className="bg-apex-bg/50 rounded-md p-4 border border-apex-border hover:border-apex-accent/20 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <div>
                        <span className="text-apex-accent font-mono font-medium">{p.name}</span>
                        {p.description && (
                          <span className="text-xs text-apex-muted ml-2">- {p.description}</span>
                        )}
                      </div>
                      <button
                        onClick={() => handleDeleteProfile(p.name)}
                        className="text-apex-muted hover:text-apex-danger transition-colors"
                        title="Delete profile"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                    <div className="grid grid-cols-3 gap-3 text-xs text-apex-muted">
                      <div>
                        <span className="text-apex-text">Sleep:</span> {p.sleep}s ({p.jitter}% jitter)
                      </div>
                      <div>
                        <span className="text-apex-text">GET URIs:</span> {p.get_uris?.length || 0}
                      </div>
                      <div>
                        <span className="text-apex-text">User Agents:</span> {p.user_agents?.length || 0}
                      </div>
                    </div>
                    {p.get_uris && p.get_uris.length > 0 && (
                      <div className="mt-2 text-xs font-mono text-apex-muted/70 truncate">
                        {p.get_uris.slice(0, 3).join(", ")}
                        {p.get_uris.length > 3 && ` +${p.get_uris.length - 3} more`}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-sm text-apex-muted/60 italic">No profiles found. Upload .yaml profiles or add them to the profiles/ directory.</div>
            )}
          </div>
        </div>
      )}

      {/* Evasion Tab */}
      {activeTab === "evasion" && (
        <div className="space-y-6">
          <div className="apex-card p-5 space-y-3 card-hover">
            <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4 text-apex-accent" />
              Windows Agent Capabilities
            </h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              {[
                { icon: Eye, title: "ETW Patching", desc: "Patches EtwEventWrite to blind ETW-based EDR telemetry" },
                { icon: Bug, title: "AMSI Patching", desc: "Patches AmsiScanBuffer to bypass script/payload scanning" },
                { icon: Shield, title: "Sleep Obfuscation (Ekko/Foliage)", desc: "XOR-encrypts agent memory during sleep to evade scanners; Ekko or Foliage ROP-based timer sleep" },
                { icon: Zap, title: "Encrypted Shellcode (AES-256/ChaCha20)", desc: "Encrypts payload at rest; AES-256 or ChaCha20 for shellcode/DLL builds" },
                { icon: Fingerprint, title: "ntdll Unhooking", desc: "Replaces hooked ntdll .text section from clean disk copy" },
                { icon: Cpu, title: "Hardware Breakpoint (DR0-DR3)", desc: "Uses debug registers for stealthy execution flow; evades software breakpoint detection" },
                { icon: Activity, title: "Indirect Syscalls (HellsGate/HalosGate)", desc: "Reads SSNs from on-disk or in-memory ntdll; executes syscall from own RWX stub, defeating call-stack EDR heuristics" },
                { icon: Terminal, title: "NtCreateUserProcess", desc: "Replaces CreateProcessA with direct NT syscall; suppresses ETW ProcessCreate events that EDR monitors" },
                { icon: Lock, title: "Heap Encryption During Sleep", desc: "XOR-scrambles agent ID, C2 host, port in-place during sleep; memory dumps reveal only scrambled bytes" },
                { icon: FileX2, title: "PE Header Stomping", desc: "Zeroes DOS/NT headers (or full page) to defeat pe-sieve, Moneta, and dump forensics" },
                { icon: FileCode, title: "BOF Loader", desc: "In-memory COFF loader with full Cobalt Strike BeaconAPI" },
                { icon: Key, title: "Token Manipulation", desc: "Steal, create, and impersonate tokens (steal_token, make_token, rev2self, getprivs, runas)" },
              ].map(({ icon: Icon, title, desc }) => (
                <div key={title} className="bg-apex-bg/50 rounded-md p-3 border border-apex-border hover:border-apex-accent/20 transition-colors">
                  <div className="flex items-center gap-2 mb-1">
                    <Icon className="w-3.5 h-3.5 text-apex-accent" />
                    <span className="text-apex-accent font-medium">{title}</span>
                  </div>
                  <p className="text-xs text-apex-muted">{desc}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="apex-card p-5 space-y-3 card-hover">
            <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4 text-apex-accent" />
              Linux / macOS Agent Capabilities
            </h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              {[
                { title: "Anti-Debug", desc: "ptrace TRACEME (Linux) / PT_DENY_ATTACH (macOS) blocks debugger attachment" },
                { title: "Process Masking", desc: "Disguises as [kworker/u:0] via prctl + argv overwrite" },
                { title: "Self-Delete", desc: "Removes binary from disk after launch, runs from memory" },
                { title: "Env Cleanup", desc: "Strips LD_PRELOAD/DYLD_INSERT_LIBRARIES monitoring shims" },
                { title: "Sandbox Detection", desc: "Checks CPU count, RAM, uptime to detect analysis environments" },
                { title: "Auto-Daemonize", desc: "Forks to background, detaches from terminal, redirects stdio" },
              ].map(({ title, desc }) => (
                <div key={title} className="bg-apex-bg/50 rounded-md p-3 border border-apex-border hover:border-apex-accent/20 transition-colors">
                  <div className="text-apex-accent font-medium mb-1">{title}</div>
                  <p className="text-xs text-apex-muted">{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
