import { useState, useEffect, useCallback } from "react";
import { useListenerStore, Listener } from "../stores/listenerStore";
import { listenerService } from "../services/listenerService";
import { usePolling } from "../hooks/usePolling";
import { Plus, Play, Square, Trash2, Radio, Loader2 } from "lucide-react";

function CreateListenerModal({ onClose, onCreate }: {
  onClose: () => void;
  onCreate: (l: Listener) => void;
}) {
  const [name, setName] = useState("");
  const [protocol, setProtocol] = useState<Listener["protocol"]>("http");
  const [bindAddr, setBindAddr] = useState("0.0.0.0");
  const [port, setPort] = useState("8080");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (loading) return;
    setLoading(true);
    setError("");
    try {
      const res = await listenerService.create({
        name: name || `${protocol}-listener`,
        protocol,
        bind_address: bindAddr,
        bind_port: parseInt(port) || 8080,
      });
      onCreate({
        id: res.id,
        name: res.name || name || `${protocol}-listener`,
        protocol: (res.protocol || protocol) as Listener["protocol"],
        bindAddress: res.bind_address || bindAddr,
        bindPort: res.bind_port || parseInt(port),
        status: (res.status || "inactive") as Listener["status"],
        config: res.config || {},
        createdAt: new Date().toISOString(),
      });
      onClose();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg || "Request failed — check teamserver connection");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={onClose}>
      <form onSubmit={handleSubmit} className="apex-card p-6 w-full max-w-md space-y-4" onClick={(e) => e.stopPropagation()}>
        <h3 className="text-lg font-semibold text-apex-text">New Listener</h3>

        <div>
          <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} className="apex-input" placeholder="my-listener" />
        </div>

        <div>
          <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">Protocol</label>
          <select
            value={protocol}
            onChange={(e) => setProtocol(e.target.value as Listener["protocol"])}
            className="apex-select"
            style={{ colorScheme: "dark" }}
          >
            <option value="http" className="bg-apex-surface text-apex-text">HTTP</option>
            <option value="https" className="bg-apex-surface text-apex-text">HTTPS</option>
            <option value="mtls" className="bg-apex-surface text-apex-text">mTLS (Mutual TLS)</option>
            <option value="dns" className="bg-apex-surface text-apex-text">DNS</option>
            <option value="tcp" className="bg-apex-surface text-apex-text">TCP</option>
            <option value="smb" className="bg-apex-surface text-apex-text">SMB</option>
          </select>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">Bind Address</label>
            <input value={bindAddr} onChange={(e) => setBindAddr(e.target.value)} className="apex-input" />
          </div>
          <div>
            <label className="block text-xs font-medium text-apex-muted mb-1 uppercase tracking-wider">Port</label>
            <input value={port} onChange={(e) => setPort(e.target.value)} className="apex-input" type="number" />
          </div>
        </div>

        {error && (
          <div className="text-xs text-apex-danger bg-apex-danger/10 px-3 py-2 rounded break-all">{error}</div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button type="button" onClick={onClose} className="apex-btn-ghost">Cancel</button>
          <button
            type="submit"
            disabled={loading}
            className="apex-btn-primary flex items-center gap-2"
          >
            {loading && <Loader2 className="w-3 h-3 animate-spin" />}
            Create
          </button>
        </div>
      </form>
    </div>
  );
}

export default function ListenersPage() {
  const { listeners, setListeners, addListener, updateListener, removeListener } = useListenerStore();
  const [showCreate, setShowCreate] = useState(false);

  const fetchListeners = useCallback(async () => {
    try {
      const data = await listenerService.list();
      setListeners(
        data.map((l) => ({
          id: l.id,
          name: l.name || l.id.slice(0, 8),
          protocol: (l.protocol || "http") as Listener["protocol"],
          bindAddress: l.bind_address || "0.0.0.0",
          bindPort: l.bind_port || 0,
          status: (l.status || "inactive") as Listener["status"],
          config: l.config || {},
          createdAt: "",
        }))
      );
    } catch {
      // Server may be down
    }
  }, [setListeners]);

  usePolling(fetchListeners, 5000);

  const toggleListener = async (l: Listener) => {
    try {
      if (l.status === "active") {
        const res = await listenerService.stop(l.id);
        updateListener(l.id, { status: (res.status || "inactive") as Listener["status"] });
      } else {
        const res = await listenerService.start(l.id);
        updateListener(l.id, { status: (res.status || "active") as Listener["status"] });
      }
    } catch (err: any) {
      console.error("Toggle listener:", err);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await listenerService.remove(id);
      removeListener(id);
    } catch (err: any) {
      console.error("Delete listener:", err);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-apex-text">Listeners</h2>
        <button onClick={() => setShowCreate(true)} className="apex-btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" /> New Listener
        </button>
      </div>

      {listeners.length === 0 ? (
        <div className="apex-card flex flex-col items-center justify-center py-16 text-apex-muted">
          <Radio className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm">No listeners configured</p>
          <p className="text-xs mt-1">Create one to start receiving agent check-ins.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {listeners.map((l) => (
            <div key={l.id} className="apex-card px-5 py-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`w-2 h-2 rounded-full ${l.status === "active" ? "bg-apex-accent animate-pulse" : "bg-apex-muted"}`} />
                <div>
                  <p className="text-sm font-medium text-apex-text">{l.name}</p>
                  <p className="text-xs text-apex-muted font-mono">
                    {l.protocol.toUpperCase()} &middot; {l.bindAddress}:{l.bindPort}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-1">
                <span className={l.status === "active" ? "apex-badge-active" : "apex-badge-inactive"}>
                  {l.status}
                </span>
                <button onClick={() => toggleListener(l)} className="apex-btn-ghost p-2" title={l.status === "active" ? "Stop" : "Start"}>
                  {l.status === "active" ? <Square className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                </button>
                <button onClick={() => handleDelete(l.id)} className="apex-btn-ghost p-2 hover:text-apex-danger" title="Delete">
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {showCreate && (
        <CreateListenerModal
          onClose={() => setShowCreate(false)}
          onCreate={addListener}
        />
      )}
    </div>
  );
}
