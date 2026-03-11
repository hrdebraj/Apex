import { useCallback, useState } from "react";
import { Monitor, Radio, Activity, Database, RefreshCw } from "lucide-react";
import { useAgentStore } from "../stores/agentStore";
import { useListenerStore } from "../stores/listenerStore";
import { agentService } from "../services/agentService";
import { listenerService } from "../services/listenerService";
import { usePolling } from "../hooks/usePolling";

interface StatCardProps {
  icon: React.ElementType;
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
}

function StatCard({ icon: Icon, label, value, sub, color = "text-apex-accent" }: StatCardProps) {
  return (
    <div className="apex-card p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-apex-muted uppercase tracking-wider">
            {label}
          </p>
          <p className="text-2xl font-bold text-apex-text mt-1">{value}</p>
          {sub && <p className="text-xs text-apex-muted mt-1">{sub}</p>}
        </div>
        <div className={`p-2 rounded-lg bg-apex-panel ${color}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </div>
  );
}

export default function DashboardPage() {
  const agents = useAgentStore((s) => s.agents);
  const setAgents = useAgentStore((s) => s.setAgents);
  const listeners = useListenerStore((s) => s.listeners);
  const setListeners = useListenerStore((s) => s.setListeners);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const fetchAll = useCallback(async () => {
    try {
      const [agentData, listenerData] = await Promise.all([
        agentService.list(),
        listenerService.list(),
      ]);
      setAgents(
        agentData.map((a) => ({
          id: a.id, hostname: a.hostname, username: a.username,
          os: a.os, arch: a.arch, pid: a.pid, processName: a.process_name,
          internalIp: a.internal_ip, externalIp: a.external_ip,
          sleep: a.sleep, jitter: a.jitter, listenerId: a.listener_id,
          firstSeen: a.first_seen, lastSeen: a.last_seen, alive: a.alive,
        }))
      );
      setListeners(
        listenerData.map((l) => ({
          id: l.id, name: l.name || l.id.slice(0, 8),
          protocol: (l.protocol || "http") as any,
          bindAddress: l.bind_address || "0.0.0.0",
          bindPort: l.bind_port || 0,
          status: (l.status || "inactive") as any,
          config: l.config || {}, createdAt: "",
        }))
      );
      setLastRefresh(new Date());
    } catch {
      // Server may be down
    }
  }, [setAgents, setListeners]);

  usePolling(fetchAll, 5000);

  const activeAgents = agents.filter((a) => a.alive).length;
  const activeListeners = listeners.filter((l) => l.status === "active").length;

  return (
    <div className="space-y-6">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={Monitor}
          label="Active Agents"
          value={activeAgents}
          sub={`${agents.length} total`}
        />
        <StatCard
          icon={Radio}
          label="Listeners"
          value={activeListeners}
          sub={`${listeners.length} configured`}
          color="text-apex-warning"
        />
        <StatCard
          icon={Activity}
          label="Tasks Today"
          value={0}
          sub="0 pending"
        />
        <StatCard
          icon={Database}
          label="Data Exfil"
          value="0 B"
          sub="Lifetime"
        />
      </div>

      {/* Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Active Agents */}
        <div className="lg:col-span-2 apex-card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-apex-text">Active Sessions</h3>
            <button onClick={fetchAll} className="apex-btn-ghost p-1.5" title="Refresh">
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>

          {agents.length === 0 ? (
            <div className="flex items-center justify-center h-48 text-apex-muted text-sm">
              No active sessions. Deploy an agent to get started.
            </div>
          ) : (
            <div className="space-y-2 max-h-64 overflow-auto">
              {agents.map((a) => (
                <div key={a.id} className="flex items-center justify-between px-3 py-2 rounded bg-apex-bg/50">
                  <div className="flex items-center gap-3">
                    <div className={`w-1.5 h-1.5 rounded-full ${a.alive ? "bg-apex-accent" : "bg-apex-muted"}`} />
                    <div>
                      <span className="text-sm text-apex-text">{a.hostname}</span>
                      <span className="text-xs text-apex-muted ml-2">{a.username}</span>
                    </div>
                  </div>
                  <span className="text-xs font-mono text-apex-muted">{a.os}/{a.arch}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* System Info */}
        <div className="apex-card p-5">
          <h3 className="text-sm font-semibold text-apex-text mb-4">
            Server Status
          </h3>
          <div className="space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-apex-muted">Listeners</span>
              <span className="text-apex-text font-mono">{activeListeners}/{listeners.length}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-apex-muted">Agents</span>
              <span className="text-apex-text font-mono">{activeAgents}/{agents.length}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-apex-muted">Server</span>
              <span className="apex-badge-active">Online</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-apex-muted">Last Refresh</span>
              <span className="text-apex-text font-mono">
                {lastRefresh ? lastRefresh.toLocaleTimeString("en-US", { hour12: false }) : "--"}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
