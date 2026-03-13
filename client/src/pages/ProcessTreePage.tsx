import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { useAgentStore } from "../stores/agentStore";
import { useTaskResultStore } from "../stores/taskResultStore";
import { taskService } from "../services/taskService";
import {
  RefreshCw,
  Search,
  XCircle,
  ChevronRight,
  ChevronDown,
  Monitor,
  Loader2,
  Cpu,
  AlertTriangle,
} from "lucide-react";

interface ProcessInfo {
  pid: number;
  ppid: number;
  name: string;
  user: string;
  children: ProcessInfo[];
}

function parseProcessList(output: string): ProcessInfo[] {
  const lines = output
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const processes: ProcessInfo[] = [];

  for (const line of lines) {
    // 4-column: PID  PPID  Name  User  (Linux ps or extended output)
    const match4 = line.match(/^(\d+)\s+(\d+)\s+(\S+)\s+(.+)$/);
    // 3-column: PID  PPID  Name  (Windows CreateToolhelp32Snapshot)
    const match3 = line.match(/^(\d+)\s+(\d+)\s+(.+)$/);

    if (match4) {
      const name = match4[3];
      const rest = match4[4].trim();
      // Heuristic: if "rest" looks like a username (no digits-only, not too long),
      // treat as user. Otherwise it's part of the process name.
      const looksLikeUser = rest.length > 0 && rest.length < 60 && !rest.includes("\\\\");
      if (looksLikeUser && !/^\d+$/.test(rest)) {
        processes.push({
          pid: parseInt(match4[1]),
          ppid: parseInt(match4[2]),
          name,
          user: rest || "—",
          children: [],
        });
      } else {
        processes.push({
          pid: parseInt(match4[1]),
          ppid: parseInt(match4[2]),
          name: name + " " + rest,
          user: "—",
          children: [],
        });
      }
    } else if (match3) {
      processes.push({
        pid: parseInt(match3[1]),
        ppid: parseInt(match3[2]),
        name: match3[3].trim(),
        user: "—",
        children: [],
      });
    }
  }

  return processes;
}

function buildTree(flat: ProcessInfo[]): ProcessInfo[] {
  const map = new Map<number, ProcessInfo>();
  for (const p of flat) {
    map.set(p.pid, { ...p, children: [] });
  }

  const roots: ProcessInfo[] = [];
  for (const p of map.values()) {
    const parent = map.get(p.ppid);
    if (parent && parent.pid !== p.pid) {
      parent.children.push(p);
    } else {
      roots.push(p);
    }
  }

  return roots;
}

function flattenWithSearch(
  tree: ProcessInfo[],
  search: string
): Set<number> {
  const matching = new Set<number>();
  const q = search.toLowerCase();

  function walkAll(node: ProcessInfo) {
    if (
      node.name.toLowerCase().includes(q) ||
      node.user.toLowerCase().includes(q) ||
      String(node.pid).includes(q)
    ) {
      matching.add(node.pid);
    }
    for (const child of node.children) walkAll(child);
  }

  for (const root of tree) walkAll(root);
  return matching;
}

function ancestorsOf(
  target: Set<number>,
  flat: ProcessInfo[]
): Set<number> {
  const ancestors = new Set<number>();
  const map = new Map<number, number>();
  for (const p of flat) map.set(p.pid, p.ppid);

  for (const pid of target) {
    let current = map.get(pid);
    while (current !== undefined && !ancestors.has(current)) {
      ancestors.add(current);
      current = map.get(current);
    }
  }
  return ancestors;
}

function ProcessNode({
  node,
  depth,
  expanded,
  onToggle,
  highlighted,
  searchMatches,
  agentPid,
  isWindows,
  onKill,
}: {
  node: ProcessInfo;
  depth: number;
  expanded: Set<number>;
  onToggle: (pid: number) => void;
  highlighted: Set<number>;
  searchMatches: Set<number>;
  agentPid: number | undefined;
  isWindows: boolean;
  onKill: (pid: number) => void;
}) {
  const isExpanded = expanded.has(node.pid);
  const hasChildren = node.children.length > 0;
  const isAgent = agentPid === node.pid;
  const isMatch = searchMatches.has(node.pid);

  return (
    <>
      <tr
        className={`border-b border-apex-border/30 transition-colors ${
          isAgent
            ? "bg-apex-accent/10"
            : isMatch
              ? "bg-apex-warning/5"
              : "hover:bg-apex-hover"
        }`}
      >
        <td className="px-4 py-2" style={{ paddingLeft: `${depth * 20 + 16}px` }}>
          <div className="flex items-center gap-1.5">
            {hasChildren ? (
              <button
                onClick={() => onToggle(node.pid)}
                className="p-0.5 rounded text-apex-muted hover:text-apex-text transition-colors"
              >
                {isExpanded ? (
                  <ChevronDown className="w-3.5 h-3.5" />
                ) : (
                  <ChevronRight className="w-3.5 h-3.5" />
                )}
              </button>
            ) : (
              <span className="w-[18px]" />
            )}
            <Cpu className={`w-3.5 h-3.5 shrink-0 ${isAgent ? "text-apex-accent" : "text-apex-muted"}`} />
            <span
              className={`font-mono text-xs ${
                isAgent
                  ? "text-apex-accent font-semibold"
                  : isMatch
                    ? "text-apex-warning"
                    : "text-apex-text"
              }`}
            >
              {node.name}
            </span>
            {isAgent && (
              <span className="ml-1 px-1.5 py-0.5 text-[10px] font-mono rounded bg-apex-accent/20 text-apex-accent border border-apex-accent/30">
                AGENT
              </span>
            )}
          </div>
        </td>
        <td className="px-4 py-2 text-xs font-mono text-apex-muted">
          {node.pid}
        </td>
        <td className="px-4 py-2 text-xs text-apex-muted">{node.user}</td>
        <td className="px-4 py-2">
          {!isAgent && (
            <button
              onClick={() => onKill(node.pid)}
              className="p-1 rounded text-apex-muted hover:text-apex-danger hover:bg-apex-danger/10 transition-colors"
              title="Kill process"
            >
              <XCircle className="w-3.5 h-3.5" />
            </button>
          )}
        </td>
      </tr>
      {isExpanded &&
        node.children
          .sort((a, b) => a.name.localeCompare(b.name))
          .filter(
            (child) =>
              !highlighted.size ||
              highlighted.has(child.pid) ||
              searchMatches.has(child.pid)
          )
          .map((child) => (
            <ProcessNode
              key={child.pid}
              node={child}
              depth={depth + 1}
              expanded={expanded}
              onToggle={onToggle}
              highlighted={highlighted}
              searchMatches={searchMatches}
              agentPid={agentPid}
              isWindows={isWindows}
              onKill={onKill}
            />
          ))}
    </>
  );
}

export default function ProcessTreePage() {
  const agents = useAgentStore((s) => s.agents);
  const selectedAgentId = useAgentStore((s) => s.selectedAgentId);
  const agent = agents.find((a) => a.id === selectedAgentId);
  const results = useTaskResultStore((s) => s.results);

  const [flatProcesses, setFlatProcesses] = useState<ProcessInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const pendingTaskId = useRef<string | null>(null);

  const isWindows = agent?.os?.toLowerCase().includes("windows") ?? false;

  const refresh = useCallback(async () => {
    if (!agent) return;
    setLoading(true);
    setError("");
    try {
      const res = await taskService.create(agent.id, "ps");
      pendingTaskId.current = res.id;
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
    }
  }, [agent]);

  useEffect(() => {
    if (agent) refresh();
  }, [agent, refresh]);

  useEffect(() => {
    if (!pendingTaskId.current) return;
    const result = results.find((r) => r.task_id === pendingTaskId.current);
    if (!result) return;

    pendingTaskId.current = null;
    const output = result.decoded || "";
    const parsed = parseProcessList(output);
    setFlatProcesses(parsed);

    const initialExpanded = new Set<number>();
    if (agent?.pid) {
      let current = parsed.find((p) => p.pid === agent.pid);
      while (current) {
        initialExpanded.add(current.ppid);
        current = parsed.find((p) => p.pid === current!.ppid);
      }
    }
    for (const p of parsed) {
      if (p.ppid === 0 || p.ppid === 1 || p.ppid === 4) {
        initialExpanded.add(p.pid);
      }
    }
    setExpanded(initialExpanded);
    setLoading(false);
  }, [results, agent]);

  const tree = useMemo(() => buildTree(flatProcesses), [flatProcesses]);

  const searchMatches = useMemo(
    () => (search ? flattenWithSearch(tree, search) : new Set<number>()),
    [tree, search]
  );

  const highlighted = useMemo(
    () => (search ? ancestorsOf(searchMatches, flatProcesses) : new Set<number>()),
    [searchMatches, flatProcesses, search]
  );

  useEffect(() => {
    if (search && searchMatches.size > 0) {
      setExpanded((prev) => {
        const next = new Set(prev);
        for (const pid of highlighted) next.add(pid);
        for (const pid of searchMatches) next.add(pid);
        return next;
      });
    }
  }, [search, searchMatches, highlighted]);

  const toggleExpand = (pid: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) next.delete(pid);
      else next.add(pid);
      return next;
    });
  };

  const handleKill = async (pid: number) => {
    if (!agent) return;
    try {
      const cmd = isWindows
        ? "shell"
        : "shell";
      const args = isWindows
        ? `taskkill /PID ${pid} /F`
        : `kill -9 ${pid}`;
      await taskService.create(agent.id, cmd, args);
      setTimeout(refresh, 1500);
    } catch (err: any) {
      console.error("Kill process:", err);
    }
  };

  if (!agent) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-apex-muted py-32">
        <Monitor className="w-12 h-12 mb-4 opacity-30" />
        <p className="text-sm font-medium">No agent selected</p>
        <p className="text-xs mt-1">
          Select an agent from the Agents page to view processes.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-apex-text">
          Process Tree
          <span className="ml-2 text-sm font-normal text-apex-muted">
            {agent.hostname}
            {flatProcesses.length > 0 && ` — ${flatProcesses.length} processes`}
          </span>
        </h2>
        <button
          onClick={refresh}
          disabled={loading}
          className="apex-btn-ghost flex items-center gap-2 px-3 py-1.5"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-apex-muted" />
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="apex-input pl-9 w-full"
          placeholder="Filter by process name, PID, user..."
        />
      </div>

      {error && (
        <div className="flex items-center gap-2 text-xs text-apex-danger bg-apex-danger/10 px-3 py-2 rounded">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          {error}
        </div>
      )}

      {loading && flatProcesses.length === 0 ? (
        <div className="apex-card flex items-center justify-center py-16">
          <Loader2 className="w-6 h-6 text-apex-muted animate-spin" />
        </div>
      ) : flatProcesses.length === 0 ? (
        <div className="apex-card flex flex-col items-center justify-center py-16 text-apex-muted">
          <Cpu className="w-10 h-10 mb-3 opacity-30" />
          <p className="text-sm">No process data</p>
          <p className="text-xs mt-1">Click Refresh to enumerate processes.</p>
        </div>
      ) : (
        <div className="apex-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-apex-border text-xs text-apex-muted uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-medium">Process</th>
                <th className="text-left px-4 py-3 font-medium w-20">PID</th>
                <th className="text-left px-4 py-3 font-medium w-32">User</th>
                <th className="w-12"></th>
              </tr>
            </thead>
            <tbody>
              {tree
                .sort((a, b) => a.name.localeCompare(b.name))
                .filter(
                  (node) =>
                    !search ||
                    highlighted.has(node.pid) ||
                    searchMatches.has(node.pid)
                )
                .map((node) => (
                  <ProcessNode
                    key={node.pid}
                    node={node}
                    depth={0}
                    expanded={expanded}
                    onToggle={toggleExpand}
                    highlighted={highlighted}
                    searchMatches={searchMatches}
                    agentPid={agent.pid}
                    isWindows={isWindows}
                    onKill={handleKill}
                  />
                ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
