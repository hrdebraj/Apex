import { useState, useRef, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { useAgentStore } from "../stores/agentStore";
import { useAuthStore } from "../stores/authStore";
import { useMitreStore } from "../stores/mitreStore";
import { useOpsecStore } from "../stores/opsecStore";
import { useTaskResultStore } from "../stores/taskResultStore";
import { useTerminalStore } from "../stores/terminalStore";
import { taskService } from "../services/taskService";
import { Terminal, ChevronRight, ShieldAlert } from "lucide-react";

export default function TerminalPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const agentFromUrl = searchParams.get("agent");
  const { agents, selectedAgentId, selectAgent } = useAgentStore();
  const operator = useAuthStore((s) => s.operator);
  const addMitreEvent = useMitreStore((s) => s.addEvent);
  const checkCommand = useOpsecStore((s) => s.checkCommand);
  const { getSession, addLine: addLineToStore, addCmdToHistory, clearSession, openAgent } = useTerminalStore();

  // Use agent from URL if provided, else selected agent
  const effectiveAgentId = agentFromUrl || selectedAgentId;
  useEffect(() => {
    if (agentFromUrl) {
      const match = agents.find((a) => a.id === agentFromUrl || a.id.startsWith(agentFromUrl));
      if (match) {
        selectAgent(match.id);
        openAgent(match.id);
      }
    } else if (selectedAgentId) {
      openAgent(selectedAgentId);
    }
  }, [agentFromUrl, selectedAgentId, agents, selectAgent, openAgent]);

  const selectedAgent = agents.find((a) => a.id === effectiveAgentId);
  const sessionKey = selectedAgent ? selectedAgent.id : "_no_agent";
  const session = getSession(sessionKey);
  const history = session.lines;

  const [input, setInput] = useState("");
  const [historyIdx, setHistoryIdx] = useState(-1);
  const [pendingCommand, setPendingCommand] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const results = useTaskResultStore((s) => s.results);
  const prevResultsLen = useRef(0);

  const addLine = (type: "input" | "output" | "error" | "info" | "warning", text: string) => {
    addLineToStore(sessionKey, { type, text });
  };

  useEffect(() => {
    const newResults = results.slice(prevResultsLen.current);
    if (newResults.length > 0 && selectedAgent) {
      prevResultsLen.current = results.length;
      for (const r of newResults) {
        if (r.agent_id === selectedAgent.id && r.decoded) {
          addLineToStore(selectedAgent.id, { type: "output", text: r.decoded });
        }
      }
    } else if (results.length !== prevResultsLen.current) {
      prevResultsLen.current = results.length;
    }
  }, [results, selectedAgent, addLineToStore]);

  useEffect(() => {
    scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight);
  }, [history]);

  const executeCommand = async (cmd: string) => {
    if (!selectedAgent) {
      addLine("error", "No agent selected. Use 'use <id>' or select from Agents tab.");
      return;
    }

    // Map to MITRE ATT&CK
    addMitreEvent(
      selectedAgent.id,
      selectedAgent.hostname,
      operator?.id || "unknown",
      cmd
    );

    try {
      const parts = cmd.split(" ");
      const command = parts[0];
      const args = parts.slice(1).join(" ");
      const task = await taskService.create(selectedAgent.id, command, args || undefined);
      addLine("info", `[queued] Task ${task.id.slice(0, 8)} -> ${selectedAgent.hostname}`);
    } catch (err: any) {
      addLine("error", `Failed: ${err.message}`);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const cmd = input.trim();
    addCmdToHistory(sessionKey, cmd);
    setHistoryIdx(-1);
    addLine("input", cmd);
    setInput("");

    // Built-in commands
    if (cmd === "clear" || cmd === "cls") {
      clearSession(sessionKey);
      return;
    }
    if (cmd === "help") {
      addLine("output", [
        "Commands:",
        "  help                  Show this message",
        "  clear / cls           Clear terminal",
        "  agents                List connected agents",
        "  use <id>              Select agent by ID prefix",
        "",
        "Agent Commands (sent to implant):",
        "  whoami                Current user + admin status",
        "  getuid                User info with PID and privilege",
        "  ps                    Process listing",
        "  pwd                   Print working directory",
        "  cd <path>             Change directory",
        "  dir / ls [path]       List directory contents",
        "  download <path>       Download file from target",
        "  upload <path>         Upload file to target",
        "  shell <cmd>           Execute shell command",
        "  exec <cmd>            Execute shell command (alias)",
        "",
        "Token Manipulation (Windows):",
        "  steal_token <pid>     Steal token from target process",
        "  make_token <user> <pass>  Create token with credentials",
        "  rev2self              Revert to original token",
        "  getprivs              List current token privileges",
        "  runas <user> <pass> <cmd> Run command as another user",
        "",
        "Sleep & Control:",
        "  sleep <sec> [jitter%] Change beacon interval",
        "  exit                  Kill the agent process",
        "",
        "Reconnaissance & Collection:",
        "  screenshot            Capture target screen (Windows)",
        "  keylogger <start|stop|dump>  Keyboard logger (Windows)",
        "  portscan <ip/cidr> <ports>   TCP port scanner",
        "",
        "BOF (Beacon Object Files):",
        "  bof <name> [args]     Execute uploaded BOF in-memory",
        "",
        "OPSEC warnings appear for risky commands.",
        "MITRE ATT&CK mappings are tracked automatically.",
      ].join("\n"));
      return;
    }
    if (cmd === "agents") {
      if (agents.length === 0) { addLine("info", "No agents connected."); return; }
      const lines = agents.map(
        (a) => `  ${a.alive ? "*" : " "} ${a.id.slice(0, 8)}  ${a.hostname}\\${a.username}  ${a.os}/${a.arch}  PID:${a.pid}`
      );
      addLine("output", "Connected agents:\n" + lines.join("\n"));
      return;
    }
    if (cmd.startsWith("use ")) {
      const prefix = cmd.slice(4).trim();
      const match = agents.find((a) => a.id.startsWith(prefix));
      if (match) {
        selectAgent(match.id);
        openAgent(match.id);
        addLine("info", `Selected: ${match.hostname} (${match.id.slice(0, 8)})`);
      } else {
        addLine("error", `No agent matching '${prefix}'`);
      }
      return;
    }

    // OPSEC check
    const warning = checkCommand(cmd);
    if (warning) {
      addLine("warning", `[OPSEC ${warning.rule.riskLevel.toUpperCase()}] ${warning.rule.description}`);
      addLine("warning", `  Alternative: ${warning.rule.alternative}`);
      setPendingCommand(cmd);
      addLine("info", "Type 'y' to execute anyway, or anything else to cancel.");
      return;
    }

    await executeCommand(cmd);
  };

  // Handle confirm/deny for OPSEC warnings
  useEffect(() => {
    if (pendingCommand && history.length > 0) {
      const last = history[history.length - 1];
      if (last.type === "input") {
        if (last.text.toLowerCase() === "y") {
          setPendingCommand(null);
          executeCommand(pendingCommand);
        } else {
          addLine("info", "Command cancelled.");
          setPendingCommand(null);
        }
      }
    }
  }, [history]);

  const cmdHistory = session.cmdHistory;
  const openedAgentIds = useTerminalStore((s) => s.openedAgentIds);
  const openedAgents = openedAgentIds
    .map((id) => agents.find((a) => a.id === id))
    .filter((a): a is NonNullable<typeof a> => !!a);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowUp" && cmdHistory.length > 0) {
      e.preventDefault();
      const newIdx = Math.min(historyIdx + 1, cmdHistory.length - 1);
      setHistoryIdx(newIdx);
      setInput(cmdHistory[newIdx]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIdx <= 0) { setHistoryIdx(-1); setInput(""); }
      else { const newIdx = historyIdx - 1; setHistoryIdx(newIdx); setInput(cmdHistory[newIdx]); }
    }
  };

  const lineColor = (type: "input" | "output" | "error" | "info" | "warning") => {
    switch (type) {
      case "input": return "text-apex-accent";
      case "output": return "text-apex-text";
      case "error": return "text-apex-danger";
      case "warning": return "text-apex-warning";
      case "info": return "text-apex-muted";
    }
  };

  return (
    <div className="h-full flex flex-col">
      {openedAgents.length > 1 && (
        <div className="flex gap-1 mb-2 overflow-x-auto">
          {openedAgents.map((a) => (
            <button
              key={a.id}
              onClick={() => {
                selectAgent(a.id);
                openAgent(a.id);
                navigate(`/terminal?agent=${a.id}`, { replace: true });
              }}
              className={`px-3 py-1.5 rounded-t text-xs font-mono transition-colors ${
                selectedAgent?.id === a.id
                  ? "bg-apex-surface border border-b-0 border-apex-border text-apex-accent"
                  : "bg-apex-bg/50 text-apex-muted hover:text-apex-text"
              }`}
            >
              {a.hostname} ({a.id.slice(0, 8)})
            </button>
          ))}
        </div>
      )}
      <div className="flex items-center gap-2 mb-3 text-xs">
        <Terminal className="w-4 h-4 text-apex-accent" />
        {selectedAgent ? (
          <span className="text-apex-text font-mono">
            {selectedAgent.username}@{selectedAgent.hostname}
            <span className="text-apex-muted"> ({selectedAgent.id.slice(0, 8)})</span>
          </span>
        ) : (
          <span className="text-apex-muted">No agent selected</span>
        )}
        {pendingCommand && (
          <span className="ml-auto flex items-center gap-1 text-apex-warning">
            <ShieldAlert className="w-3.5 h-3.5" />
            OPSEC confirmation pending
          </span>
        )}
      </div>

      <div
        ref={scrollRef}
        onClick={() => inputRef.current?.focus()}
        className="flex-1 apex-card p-4 overflow-auto font-mono text-sm cursor-text"
      >
        {history.map((line, i) => (
          <div key={i} className={`${lineColor(line.type)} whitespace-pre-wrap leading-relaxed`}>
            {line.type === "input" && <span className="text-apex-accent mr-2">&gt;</span>}
            {line.type === "warning" && <span className="mr-1">!</span>}
            {line.text}
          </div>
        ))}

        <form onSubmit={handleSubmit} className="flex items-center mt-1">
          <ChevronRight className="w-4 h-4 text-apex-accent mr-1 flex-shrink-0" />
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            className="flex-1 bg-transparent text-apex-text outline-none font-mono text-sm caret-apex-accent"
            spellCheck={false}
            autoFocus
          />
        </form>
      </div>
    </div>
  );
}
