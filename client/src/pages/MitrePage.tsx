import { useState } from "react";
import { useMitreStore, MitreEvent } from "../stores/mitreStore";
import { TACTIC_ORDER, TACTIC_COLORS, MITRE_TECHNIQUES } from "../services/mitreData";
import { Crosshair, Trash2, Clock, Grid3X3, List } from "lucide-react";

function TacticColumn({ tactic, events }: { tactic: string; events: MitreEvent[] }) {
  const techniques = Object.values(MITRE_TECHNIQUES).filter((t) => t.tactic === tactic);
  const firedIds = new Set(events.map((e) => e.techniqueId));
  const color = TACTIC_COLORS[tactic] || "#6e6e8a";

  return (
    <div className="min-w-[150px]">
      <div
        className="text-[10px] font-bold uppercase tracking-wider px-2 py-1.5 rounded-t text-center"
        style={{ backgroundColor: `${color}20`, color }}
      >
        {tactic}
      </div>
      <div className="space-y-0.5">
        {techniques.map((t) => {
          const fired = firedIds.has(t.id);
          const count = events.filter((e) => e.techniqueId === t.id).length;
          return (
            <div
              key={t.id}
              className={`px-2 py-1.5 text-[11px] border-l-2 transition-colors ${
                fired
                  ? "bg-apex-panel border-l-apex-accent text-apex-text"
                  : "bg-apex-surface/50 border-l-transparent text-apex-muted/50"
              }`}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono">{t.id}</span>
                {fired && (
                  <span className="text-[9px] font-bold text-apex-accent">{count}x</span>
                )}
              </div>
              <div className="text-[10px] truncate">{t.name}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function MitrePage() {
  const { events, clearEvents } = useMitreStore();
  const [activeTab, setActiveTab] = useState<"matrix" | "timeline">("matrix");

  const activeTactics = TACTIC_ORDER.filter((tactic) =>
    Object.values(MITRE_TECHNIQUES).some((t) => t.tactic === tactic)
  );

  return (
    <div className="space-y-4 h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-2">
          <Crosshair className="w-5 h-5 text-apex-accent" />
          <h2 className="text-lg font-semibold text-apex-text">MITRE ATT&CK Mapping</h2>
          <span className="text-xs text-apex-muted">({events.length} events mapped)</span>
        </div>
        {events.length > 0 && (
          <button onClick={clearEvents} className="apex-btn-ghost flex items-center gap-1.5 text-xs">
            <Trash2 className="w-3 h-3" /> Clear
          </button>
        )}
      </div>

      {/* Tab Switcher */}
      <div className="flex gap-1 bg-apex-bg rounded-lg p-1 border border-apex-border flex-shrink-0">
        <button
          onClick={() => setActiveTab("matrix")}
          className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            activeTab === "matrix"
              ? "bg-apex-accent/20 text-apex-accent border border-apex-accent/40"
              : "text-apex-muted hover:text-apex-text hover:bg-apex-surface"
          }`}
        >
          <Grid3X3 className="w-4 h-4" />
          ATT&CK Matrix
        </button>
        <button
          onClick={() => setActiveTab("timeline")}
          className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            activeTab === "timeline"
              ? "bg-apex-accent/20 text-apex-accent border border-apex-accent/40"
              : "text-apex-muted hover:text-apex-text hover:bg-apex-surface"
          }`}
        >
          <Clock className="w-4 h-4" />
          Event Timeline
          {events.length > 0 && (
            <span className="text-[10px] bg-apex-accent/20 text-apex-accent px-1.5 py-0.5 rounded-full font-bold">
              {events.length}
            </span>
          )}
        </button>
      </div>

      {/* Matrix Tab */}
      {activeTab === "matrix" && (
        <div className="apex-card p-4 overflow-auto flex-1">
          <div className="flex gap-1 min-w-max">
            {activeTactics.map((tactic) => (
              <TacticColumn key={tactic} tactic={tactic} events={events} />
            ))}
          </div>
        </div>
      )}

      {/* Timeline Tab */}
      {activeTab === "timeline" && (
        <div className="apex-card p-4 flex-1 overflow-auto">
          <h3 className="text-sm font-semibold text-apex-text mb-3 flex items-center gap-2">
            <List className="w-4 h-4 text-apex-accent" />
            Event Timeline
          </h3>
          {events.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-apex-muted text-sm gap-3">
              <Clock className="w-8 h-8 text-apex-muted/30" />
              <p>Execute commands against agents to see MITRE ATT&CK mappings here.</p>
              <p className="text-xs text-apex-muted/60">
                Commands like whoami, ps, shell, download are automatically mapped to techniques.
              </p>
            </div>
          ) : (
            <div className="space-y-1.5">
              {[...events].reverse().map((event) => (
                <div key={event.id} className="flex items-center gap-3 px-3 py-2.5 rounded bg-apex-bg/50 text-xs hover:bg-apex-bg/80 transition-colors">
                  <Clock className="w-3 h-3 text-apex-muted flex-shrink-0" />
                  <span className="text-apex-muted font-mono w-16 flex-shrink-0">
                    {event.timestamp.toLocaleTimeString("en-US", { hour12: false })}
                  </span>
                  <span
                    className="px-1.5 py-0.5 rounded text-[10px] font-bold flex-shrink-0"
                    style={{
                      backgroundColor: `${TACTIC_COLORS[event.technique.tactic] || "#6e6e8a"}20`,
                      color: TACTIC_COLORS[event.technique.tactic] || "#6e6e8a",
                    }}
                  >
                    {event.techniqueId}
                  </span>
                  <span className="text-apex-text">{event.technique.name}</span>
                  <span className="text-apex-muted">on</span>
                  <span className="text-apex-accent font-mono">{event.agentHostname}</span>
                  <span className="text-apex-muted font-mono ml-auto">$ {event.command}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
