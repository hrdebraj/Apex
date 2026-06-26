import { useState, useRef, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { useAuthStore } from "../stores/authStore";
import { Shield, Server, Key, Info, Upload, CheckCircle, XCircle, Loader2 } from "lucide-react";

export default function SettingsPage() {
  const { operator, serverAddr, mtlsEnabled, setMtls } = useAuthStore();
  const [certFile, setCertFile] = useState<string>("");
  const [keyFile, setKeyFile] = useState<string>("");
  const [certPem, setCertPem] = useState<string>("");
  const [keyPem, setKeyPem] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<{ ok: boolean; msg: string } | null>(null);
  const certRef = useRef<HTMLInputElement>(null);
  const keyRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    invoke<boolean>("is_mtls_active").then((active) => {
      if (active !== mtlsEnabled) setMtls(active);
    });
  }, []);

  const readFile = (file: File): Promise<string> =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = () => reject(reader.error);
      reader.readAsText(file);
    });

  const handleCertSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setCertFile(file.name);
    setCertPem(await readFile(file));
  };

  const handleKeySelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setKeyFile(file.name);
    setKeyPem(await readFile(file));
  };

  const handleLoadCert = async () => {
    if (!certPem || !keyPem) {
      setStatus({ ok: false, msg: "Select both certificate and key files" });
      return;
    }
    setLoading(true);
    setStatus(null);
    try {
      await invoke("load_mtls_cert", { certPem, keyPem });
      setMtls(true);
      setStatus({ ok: true, msg: "mTLS enabled — all API requests now use client certificate" });
    } catch (err: any) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatus({ ok: false, msg });
    } finally {
      setLoading(false);
    }
  };

  const handleDisable = async () => {
    try {
      await invoke("clear_mtls");
      setMtls(false);
      setCertFile("");
      setKeyFile("");
      setCertPem("");
      setKeyPem("");
      setStatus({ ok: true, msg: "mTLS disabled — using standard TLS" });
    } catch (err: any) {
      const msg = err instanceof Error ? err.message : String(err);
      setStatus({ ok: false, msg });
    }
  };

  return (
    <div className="max-w-2xl space-y-6">
      <h2 className="text-lg font-semibold text-apex-text">Settings</h2>

      {/* Connection Info */}
      <div className="apex-card p-5 space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-apex-text">
          <Server className="w-4 h-4 text-apex-accent" />
          Connection
        </div>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-xs text-apex-muted uppercase tracking-wider mb-1">Server</p>
            <p className="font-mono text-apex-text">{serverAddr}</p>
          </div>
          <div>
            <p className="text-xs text-apex-muted uppercase tracking-wider mb-1">Status</p>
            <span className="apex-badge-active">Connected</span>
          </div>
        </div>
      </div>

      {/* Operator Info */}
      <div className="apex-card p-5 space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-apex-text">
          <Shield className="w-4 h-4 text-apex-accent" />
          Operator
        </div>
        <div className="grid grid-cols-3 gap-4 text-sm">
          <div>
            <p className="text-xs text-apex-muted uppercase tracking-wider mb-1">Username</p>
            <p className="text-apex-text">{operator?.username}</p>
          </div>
          <div>
            <p className="text-xs text-apex-muted uppercase tracking-wider mb-1">Role</p>
            <span className="apex-badge-active">{operator?.role}</span>
          </div>
          <div>
            <p className="text-xs text-apex-muted uppercase tracking-wider mb-1">ID</p>
            <p className="font-mono text-apex-text">{operator?.id}</p>
          </div>
        </div>
      </div>

      {/* Security / mTLS */}
      <div className="apex-card p-5 space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-apex-text">
          <Key className="w-4 h-4 text-apex-accent" />
          Security
        </div>

        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-apex-text">mTLS Authentication</p>
            <p className="text-xs text-apex-muted">Mutual TLS between client and server</p>
          </div>
          {mtlsEnabled ? (
            <span className="apex-badge-active">Active</span>
          ) : (
            <span className="apex-badge-inactive">Not configured</span>
          )}
        </div>

        {!mtlsEnabled ? (
          <div className="space-y-3 pt-2 border-t border-apex-border">
            <div>
              <label className="block text-xs text-apex-muted uppercase tracking-wider mb-1.5">
                Client Certificate (.crt / .pem)
              </label>
              <div className="flex items-center gap-2">
                <input
                  ref={certRef}
                  type="file"
                  accept=".crt,.pem,.cert"
                  onChange={handleCertSelect}
                  className="hidden"
                />
                <button
                  onClick={() => certRef.current?.click()}
                  className="apex-btn-ghost text-xs flex items-center gap-1"
                >
                  <Upload className="w-3 h-3" />
                  Select
                </button>
                <span className="text-xs text-apex-muted font-mono truncate">
                  {certFile || "No file selected"}
                </span>
              </div>
            </div>

            <div>
              <label className="block text-xs text-apex-muted uppercase tracking-wider mb-1.5">
                Client Key (.key / .pem)
              </label>
              <div className="flex items-center gap-2">
                <input
                  ref={keyRef}
                  type="file"
                  accept=".key,.pem"
                  onChange={handleKeySelect}
                  className="hidden"
                />
                <button
                  onClick={() => keyRef.current?.click()}
                  className="apex-btn-ghost text-xs flex items-center gap-1"
                >
                  <Upload className="w-3 h-3" />
                  Select
                </button>
                <span className="text-xs text-apex-muted font-mono truncate">
                  {keyFile || "No file selected"}
                </span>
              </div>
            </div>

            <button
              onClick={handleLoadCert}
              disabled={loading || !certPem || !keyPem}
              className="apex-btn-primary text-xs py-1.5 px-4 flex items-center gap-2 disabled:opacity-50"
            >
              {loading ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <Key className="w-3 h-3" />
              )}
              Enable mTLS
            </button>
          </div>
        ) : (
          <div className="pt-2 border-t border-apex-border">
            <button
              onClick={handleDisable}
              className="apex-btn-ghost text-xs text-red-400 hover:text-red-300"
            >
              Disable mTLS
            </button>
          </div>
        )}

        {status && (
          <div
            className={`flex items-start gap-2 px-3 py-2 rounded text-xs ${
              status.ok
                ? "bg-apex-accent/10 border border-apex-accent/20 text-apex-accent"
                : "bg-apex-danger/10 border border-apex-danger/20 text-apex-danger"
            }`}
          >
            {status.ok ? (
              <CheckCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            )}
            <span>{status.msg}</span>
          </div>
        )}
      </div>

      {/* About */}
      <div className="apex-card p-5">
        <div className="flex items-center gap-2 text-sm font-semibold text-apex-text mb-3">
          <Info className="w-4 h-4 text-apex-accent" />
          About
        </div>
        <div className="text-xs text-apex-muted space-y-1 font-mono">
          <p>Apex C2 Framework</p>
          <p>Team Server: Go | Client: Tauri + React | Agent: C/C++</p>
          <p>Protocol: gRPC with mTLS</p>
        </div>
      </div>
    </div>
  );
}
