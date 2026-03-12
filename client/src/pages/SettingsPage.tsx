import { useAuthStore } from "../stores/authStore";
import { Shield, Server, Key, Info } from "lucide-react";

export default function SettingsPage() {
  const { operator, serverAddr } = useAuthStore();

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

      {/* Security */}
      <div className="apex-card p-5 space-y-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-apex-text">
          <Key className="w-4 h-4 text-apex-accent" />
          Security
        </div>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-apex-text">mTLS Authentication</p>
              <p className="text-xs text-apex-muted">Mutual TLS between client and server</p>
            </div>
            <span className="apex-badge-inactive">Not configured</span>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-apex-text">Certificate</p>
              <p className="text-xs text-apex-muted">Client certificate for gRPC auth</p>
            </div>
            <button className="apex-btn-ghost text-xs">Upload</button>
          </div>
        </div>
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
