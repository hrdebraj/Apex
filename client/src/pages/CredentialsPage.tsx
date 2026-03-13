import { useState, useEffect } from "react";
import { apiClient } from "../services/api";
import {
  Plus,
  Trash2,
  Search,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  X,
} from "lucide-react";

interface Credential {
  id: string;
  agent_id: string;
  domain: string;
  username: string;
  secret: string;
  type: string;
  source: string;
  created_at: string;
}

const TYPE_STYLES: Record<string, string> = {
  ntlm: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  plaintext: "bg-red-500/15 text-red-400 border-red-500/30",
  kerberos: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  token: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  certificate: "bg-green-500/15 text-green-400 border-green-500/30",
};

function typeBadge(type: string) {
  const style = TYPE_STYLES[type] ?? "bg-apex-muted/15 text-apex-muted border-apex-muted/30";
  return (
    <span className={`px-2 py-0.5 text-xs font-mono rounded border ${style}`}>
      {type}
    </span>
  );
}

function timeAgo(dateStr: string): string {
  if (!dateStr) return "—";
  const diff = Date.now() - new Date(dateStr).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function AddCredentialModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (c: Credential) => void;
}) {
  const [username, setUsername] = useState("");
  const [secret, setSecret] = useState("");
  const [type, setType] = useState("plaintext");
  const [domain, setDomain] = useState("");
  const [source, setSource] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async () => {
    if (!username || !secret) {
      setError("Username and secret are required");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const res = await apiClient.post<Credential>("/api/credentials", {
        username,
        secret,
        type,
        domain: domain || undefined,
        source: source || undefined,
      });
      onCreated(res);
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="apex-card p-6 w-full max-w-md space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-apex-text">
            Add Credential
          </h3>
          <button onClick={onClose} className="apex-btn-ghost p-1">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
              Username *
            </label>
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="apex-input"
              placeholder="admin"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
              Domain
            </label>
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              className="apex-input"
              placeholder="CORP"
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
            Secret *
          </label>
          <input
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            className="apex-input font-mono"
            placeholder="password or hash"
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
              Type
            </label>
            <select
              value={type}
              onChange={(e) => setType(e.target.value)}
              className="apex-select"
              style={{ colorScheme: "dark" }}
            >
              <option value="plaintext" className="bg-apex-surface text-apex-text">Plaintext</option>
              <option value="ntlm" className="bg-apex-surface text-apex-text">NTLM</option>
              <option value="kerberos" className="bg-apex-surface text-apex-text">Kerberos</option>
              <option value="token" className="bg-apex-surface text-apex-text">Token</option>
              <option value="certificate" className="bg-apex-surface text-apex-text">Certificate</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">
              Source
            </label>
            <input
              value={source}
              onChange={(e) => setSource(e.target.value)}
              className="apex-input"
              placeholder="mimikatz"
            />
          </div>
        </div>

        {error && (
          <div className="text-xs text-apex-danger bg-apex-danger/10 px-3 py-2 rounded">
            {error}
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button onClick={onClose} className="apex-btn-ghost">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="apex-btn-primary flex items-center gap-2"
          >
            {loading && <Loader2 className="w-3 h-3 animate-spin" />}
            Add
          </button>
        </div>
      </div>
    </div>
  );
}

export default function CredentialsPage() {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [visibleSecrets, setVisibleSecrets] = useState<Set<string>>(new Set());

  const fetchCredentials = async () => {
    try {
      const data = await apiClient.get<Credential[]>("/api/credentials");
      setCredentials(data);
    } catch {
      // server may be down
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCredentials();
  }, []);

  const handleDelete = async (id: string) => {
    try {
      await apiClient.delete(`/api/credentials/${id}`);
      setCredentials((prev) => prev.filter((c) => c.id !== id));
    } catch (err: any) {
      console.error("Delete credential:", err);
    }
  };

  const toggleSecret = (id: string) => {
    setVisibleSecrets((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const filtered = credentials.filter((c) => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      c.username.toLowerCase().includes(q) ||
      c.domain.toLowerCase().includes(q) ||
      c.type.toLowerCase().includes(q) ||
      c.source.toLowerCase().includes(q) ||
      c.agent_id?.toLowerCase().includes(q)
    );
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-apex-text">
          Credentials
          <span className="ml-2 text-sm font-normal text-apex-muted">
            ({credentials.length})
          </span>
        </h2>
        <button
          onClick={() => setShowModal(true)}
          className="apex-btn-primary flex items-center gap-2"
        >
          <Plus className="w-4 h-4" /> Add Credential
        </button>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-apex-muted" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="apex-input pl-9 w-full"
          placeholder="Filter by username, domain, type, source..."
        />
      </div>

      {loading ? (
        <div className="apex-card flex items-center justify-center py-16">
          <Loader2 className="w-6 h-6 text-apex-muted animate-spin" />
        </div>
      ) : credentials.length === 0 ? (
        <div className="apex-card flex flex-col items-center justify-center py-16 text-apex-muted">
          <KeyRound className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm">No credentials captured</p>
          <p className="text-xs mt-1">
            Harvested credentials will appear here.
          </p>
        </div>
      ) : (
        <div className="apex-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-apex-border text-xs text-apex-muted uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-medium">Type</th>
                <th className="text-left px-4 py-3 font-medium">
                  Domain\User
                </th>
                <th className="text-left px-4 py-3 font-medium">Secret</th>
                <th className="text-left px-4 py-3 font-medium">Source</th>
                <th className="text-left px-4 py-3 font-medium">Agent</th>
                <th className="text-left px-4 py-3 font-medium">Captured</th>
                <th className="w-10"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((cred) => (
                <tr
                  key={cred.id}
                  className="border-b border-apex-border/50 hover:bg-apex-hover transition-colors"
                >
                  <td className="px-4 py-3">{typeBadge(cred.type)}</td>
                  <td className="px-4 py-3 font-mono text-apex-text">
                    {cred.domain ? `${cred.domain}\\` : ""}
                    {cred.username}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-apex-text truncate max-w-[200px]">
                        {visibleSecrets.has(cred.id)
                          ? cred.secret
                          : "••••••••••••"}
                      </span>
                      <button
                        onClick={() => toggleSecret(cred.id)}
                        className="p-1 rounded text-apex-muted hover:text-apex-text transition-colors"
                      >
                        {visibleSecrets.has(cred.id) ? (
                          <EyeOff className="w-3.5 h-3.5" />
                        ) : (
                          <Eye className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-apex-muted">
                    {cred.source || "—"}
                  </td>
                  <td className="px-4 py-3 font-mono text-apex-muted">
                    {cred.agent_id ? cred.agent_id.slice(0, 8) : "manual"}
                  </td>
                  <td className="px-4 py-3 text-apex-muted">
                    {timeAgo(cred.created_at)}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => handleDelete(cred.id)}
                      className="p-1.5 rounded text-apex-muted hover:text-apex-danger hover:bg-apex-danger/10 transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-4 py-8 text-center text-apex-muted text-xs"
                  >
                    No credentials match your filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {showModal && (
        <AddCredentialModal
          onClose={() => setShowModal(false)}
          onCreated={(c) => setCredentials((prev) => [...prev, c])}
        />
      )}
    </div>
  );
}
