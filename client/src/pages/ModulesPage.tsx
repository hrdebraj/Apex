import { useCallback, useEffect, useState } from "react";
import { payloadService } from "../services/payloadService";
import { FileCode, Upload, Shield, HardDrive, Trash2, RefreshCw } from "lucide-react";

interface BOFFile {
  id: string;
  name: string;
  size?: number;
  hash?: string;
  uploaded_at?: string;
}

export default function ModulesPage() {
  const [bofFiles, setBofFiles] = useState<BOFFile[]>([]);
  const [bofUploading, setBofUploading] = useState(false);
  const [bofMessage, setBofMessage] = useState<string | null>(null);
  const [byovdEnabled, setByovdEnabled] = useState(false);
  const [byovdDriverPath, setByovdDriverPath] = useState("");
  const [byovdMessage, setByovdMessage] = useState<string | null>(null);

  const fetchBOFs = useCallback(async () => {
    try {
      const data = await payloadService.listBOFs();
      setBofFiles(Array.isArray(data) ? data : []);
    } catch {
      setBofFiles([]);
    }
  }, []);

  useEffect(() => {
    fetchBOFs();
  }, [fetchBOFs]);

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

  const formatSize = (bytes?: number) => {
    if (!bytes) return "—";
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold text-apex-text">Modules</h2>
        <p className="text-sm text-apex-muted mt-0.5">
          BOF (Beacon Object Files) and BYOVD (Bring Your Own Vulnerable Driver).
          BOFs execute in-memory via the agent's COFF loader — no disk drop.
        </p>
      </div>

      {/* BOF Section */}
      <div className="apex-card p-5 space-y-4">
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
                  <tr key={b.id} className="border-t border-apex-border hover:bg-apex-surface/50">
                    <td className="px-3 py-2 font-mono text-apex-text">{b.name}</td>
                    <td className="px-3 py-2 text-apex-muted">{formatSize(b.size)}</td>
                    <td className="px-3 py-2 text-apex-muted font-mono text-xs">{b.hash || "—"}</td>
                    <td className="px-3 py-2 text-apex-muted text-xs">
                      {b.uploaded_at ? new Date(b.uploaded_at).toLocaleString() : "—"}
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

      {/* BYOVD Section */}
      <div className="apex-card p-5 space-y-4">
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
        {byovdMessage && (
          <div className="text-sm text-apex-muted">{byovdMessage}</div>
        )}
      </div>

      {/* Evasion Info Card */}
      <div className="apex-card p-5 space-y-3">
        <h3 className="text-sm font-medium text-apex-text uppercase tracking-wider flex items-center gap-2">
          <Shield className="w-4 h-4 text-apex-accent" />
          Agent Evasion Capabilities
        </h3>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div className="bg-apex-bg/50 rounded-md p-3 border border-apex-border">
            <div className="text-apex-accent font-medium mb-1">ETW Patching</div>
            <div className="text-xs text-apex-muted">Patches EtwEventWrite to blind ETW-based EDR telemetry</div>
          </div>
          <div className="bg-apex-bg/50 rounded-md p-3 border border-apex-border">
            <div className="text-apex-accent font-medium mb-1">AMSI Patching</div>
            <div className="text-xs text-apex-muted">Patches AmsiScanBuffer to bypass script/payload scanning</div>
          </div>
          <div className="bg-apex-bg/50 rounded-md p-3 border border-apex-border">
            <div className="text-apex-accent font-medium mb-1">Encrypted Sleep (Ekko)</div>
            <div className="text-xs text-apex-muted">XOR-encrypts agent memory during sleep to evade memory scanners</div>
          </div>
          <div className="bg-apex-bg/50 rounded-md p-3 border border-apex-border">
            <div className="text-apex-accent font-medium mb-1">ntdll Unhooking</div>
            <div className="text-xs text-apex-muted">Replaces hooked ntdll .text section from clean disk copy</div>
          </div>
          <div className="bg-apex-bg/50 rounded-md p-3 border border-apex-border">
            <div className="text-apex-accent font-medium mb-1">BOF Loader</div>
            <div className="text-xs text-apex-muted">In-memory COFF loader with full BeaconAPI compatibility</div>
          </div>
          <div className="bg-apex-bg/50 rounded-md p-3 border border-apex-border">
            <div className="text-apex-accent font-medium mb-1">Runtime Sleep Control</div>
            <div className="text-xs text-apex-muted">Switch between short-haul (interactive) and long-haul (stealth) profiles</div>
          </div>
        </div>
      </div>
    </div>
  );
}
