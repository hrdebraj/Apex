import { useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAgentStore, Agent } from "../stores/agentStore";
import { agentService } from "../services/agentService";
import { usePolling } from "../hooks/usePolling";
import { Monitor, Cpu, Clock, Trash2, Package, Terminal } from "lucide-react";

function timeAgo(dateStr: string): string {
  if (!dateStr) return "never";
  const diff = Date.now() - new Date(dateStr).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ago`;
}

function AgentRow({ agent, onSelect, isSelected, onOpenTerminal }: {
  agent: Agent;
  onSelect: () => void;
  isSelected: boolean;
  onOpenTerminal: () => void;
}) {
  const removeAgent = useAgentStore((s) => s.removeAgent);

  const handleOpenTerminal = (e: React.MouseEvent) => {
    e.stopPropagation();
    onOpenTerminal();
  };

  const handleRemove = async (e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await agentService.remove(agent.id);
      removeAgent(agent.id);
    } catch (err) {
      console.error("Remove agent:", err);
    }
  };

  return (
    <div
      onClick={onSelect}
      className={`apex-card px-5 py-4 cursor-pointer transition-colors ${
        isSelected ? "border-apex-accent/50 bg-apex-accent/5" : "hover:bg-apex-hover"
      }`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <div className="relative">
            <Monitor className="w-5 h-5 text-apex-muted" />
            <div className={`absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full border border-apex-surface ${
              agent.alive ? "bg-apex-accent" : "bg-apex-muted"
            }`} />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-apex-text">
                {agent.hostname}
              </span>
              <span className="text-xs font-mono text-apex-muted">
                {agent.id.slice(0, 8)}
              </span>
            </div>
            <div className="flex items-center gap-3 mt-0.5 text-xs text-apex-muted">
              <span>{agent.username}</span>
              <span className="font-mono">{agent.internalIp}</span>
              <span className="flex items-center gap-1">
                <Cpu className="w-3 h-3" />
                {agent.os}/{agent.arch}
              </span>
              <span>PID {agent.pid}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleOpenTerminal}
            className="p-2 rounded text-apex-muted hover:text-apex-accent hover:bg-apex-accent/10 transition-colors"
            title="Beacon Terminal"
          >
            <Terminal className="w-4 h-4" />
          </button>
          <div className="text-right text-xs">
            <div className="flex items-center gap-1 text-apex-muted">
              <Clock className="w-3 h-3" />
              {timeAgo(agent.lastSeen)}
            </div>
            <div className="text-apex-muted font-mono mt-0.5">
              {agent.sleep}s / {agent.jitter}%
            </div>
          </div>
          <button
            onClick={handleRemove}
            className="p-2 rounded text-apex-muted hover:text-apex-danger hover:bg-apex-danger/10 transition-colors"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

export default function AgentsPage() {
  const navigate = useNavigate();
  const { agents, setAgents, selectedAgentId, selectAgent } = useAgentStore();

  const fetchAgents = useCallback(async () => {
    try {
      const data = await agentService.list();
      setAgents(
        data.map((a) => ({
          id: a.id,
          hostname: a.hostname,
          username: a.username,
          os: a.os,
          arch: a.arch,
          pid: a.pid,
          processName: a.process_name,
          internalIp: a.internal_ip,
          externalIp: a.external_ip,
          sleep: a.sleep,
          jitter: a.jitter,
          listenerId: a.listener_id,
          firstSeen: a.first_seen,
          lastSeen: a.last_seen,
          alive: a.alive,
        }))
      );
    } catch {
      // Server may be down
    }
  }, [setAgents]);

  usePolling(fetchAgents, 3000);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-apex-text">
          Agents
          <span className="ml-2 text-sm font-normal text-apex-muted">
            ({agents.filter((a) => a.alive).length} active)
          </span>
        </h2>
        <Link
          to="/agent-builder"
          className="apex-btn apex-btn-primary flex items-center gap-2"
        >
          <Package className="w-4 h-4" />
          Agent Builder
        </Link>
      </div>

      {agents.length === 0 ? (
        <div className="apex-card flex flex-col items-center justify-center py-16 text-apex-muted">
          <Monitor className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm">No agents connected</p>
          <p className="text-xs mt-1">
            Deploy a payload and wait for a check-in.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {agents.map((agent) => (
            <AgentRow
              key={agent.id}
              agent={agent}
              isSelected={selectedAgentId === agent.id}
              onSelect={() => selectAgent(agent.id)}
              onOpenTerminal={() => {
                selectAgent(agent.id);
                navigate(`/terminal?agent=${agent.id}`);
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}
