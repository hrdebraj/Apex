import { useLocation } from "react-router-dom";
import { useAgentStore } from "../../stores/agentStore";
import { useListenerStore } from "../../stores/listenerStore";
import { useMitreStore } from "../../stores/mitreStore";
import { Wifi, Monitor, Clock, Crosshair } from "lucide-react";
import { useEffect, useState } from "react";

const pageTitles: Record<string, string> = {
  "/dashboard": "Dashboard",
  "/listeners": "Listeners",
  "/agents": "Agents",
  "/agent-builder": "Agent Builder",
  "/terminal": "Terminal",
  "/modules": "Modules",
  "/graph": "Attack Graph",
  "/mitre": "MITRE ATT&CK",
  "/settings": "Settings",
};

export default function TopBar() {
  const location = useLocation();
  const agents = useAgentStore((s) => s.agents);
  const listeners = useListenerStore((s) => s.listeners);
  const mitreEvents = useMitreStore((s) => s.events);
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const interval = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(interval);
  }, []);

  const activeAgents = agents.filter((a) => a.alive).length;
  const activeListeners = listeners.filter((l) => l.status === "active").length;
  const title = pageTitles[location.pathname] || "Apex";

  return (
    <header className="h-12 bg-apex-surface border-b border-apex-border flex items-center justify-between px-5">
      <h2 className="text-sm font-semibold text-apex-text">{title}</h2>

      <div className="flex items-center gap-5">
        <div className="flex items-center gap-1.5 text-xs text-apex-muted">
          <Wifi className="w-3.5 h-3.5 text-apex-accent" />
          <span>
            <span className="text-apex-text font-medium">{activeListeners}</span>{" "}
            listeners
          </span>
        </div>

        <div className="flex items-center gap-1.5 text-xs text-apex-muted">
          <Monitor className="w-3.5 h-3.5 text-apex-accent" />
          <span>
            <span className="text-apex-text font-medium">{activeAgents}</span>{" "}
            agents
          </span>
        </div>

        <div className="flex items-center gap-1.5 text-xs text-apex-muted">
          <Crosshair className="w-3.5 h-3.5 text-apex-accent" />
          <span>
            <span className="text-apex-text font-medium">{mitreEvents.length}</span>{" "}
            TTPs
          </span>
        </div>

        <div className="flex items-center gap-1.5 text-xs text-apex-muted">
          <Clock className="w-3.5 h-3.5" />
          <span className="font-mono">
            {time.toLocaleTimeString("en-US", { hour12: false })}
          </span>
        </div>
      </div>
    </header>
  );
}
