import { useState, useEffect, useCallback, useRef } from "react";
import { useAgentStore } from "../stores/agentStore";
import { useTaskResultStore } from "../stores/taskResultStore";
import { taskService } from "../services/taskService";
import {
  Folder,
  File,
  Upload,
  Download,
  RefreshCw,
  ArrowLeft,
  ChevronRight,
  Monitor,
  Loader2,
  AlertTriangle,
} from "lucide-react";

interface FileEntry {
  name: string;
  isDir: boolean;
  size: string;
  modified: string;
  permissions: string;
}

function parseWindowsDir(output: string): FileEntry[] {
  const entries: FileEntry[] = [];
  const lines = output.split("\n").map((l) => l.trimEnd());
  for (const line of lines) {
    // Standard cmd dir format:  MM/DD/YYYY  HH:MM AM/PM  <DIR>|size  name
    // Also handles leading whitespace in cmd output
    const match = line.match(
      /(\d{1,2}[\/-]\d{1,2}[\/-]\d{2,4})\s+(\d{1,2}:\d{2}\s*[AP]?M?)\s+(<DIR>|[\d,]+)\s+(.+)/i
    );
    if (!match) continue;
    const [, date, time, sizeOrDir, name] = match;
    const trimmedName = name.trim();
    if (trimmedName === "." || trimmedName === "..") continue;
    entries.push({
      name: trimmedName,
      isDir: sizeOrDir === "<DIR>",
      size: sizeOrDir === "<DIR>" ? "—" : formatBytes(parseInt(sizeOrDir.replace(/,/g, ""))),
      modified: `${date} ${time}`,
      permissions: "—",
    });
  }
  return entries;
}

function parseLinuxLs(output: string): FileEntry[] {
  const entries: FileEntry[] = [];
  const lines = output.split("\n").filter(Boolean);
  for (const line of lines) {
    if (line.startsWith("total")) continue;
    const match = line.match(
      /^([drwxlsStT\-]{10})\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+\s+\d+\s+[\d:]+)\s+(.+)$/
    );
    if (!match) continue;
    const [, perms, , , size, modified, name] = match;
    if (name === "." || name === "..") continue;
    const isLink = name.includes(" -> ");
    const displayName = isLink ? name.split(" -> ")[0] : name;
    entries.push({
      name: displayName,
      isDir: perms.startsWith("d"),
      size: formatBytes(parseInt(size)),
      modified,
      permissions: perms,
    });
  }
  return entries;
}

function formatBytes(bytes: number): string {
  if (isNaN(bytes)) return "—";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

function joinPath(base: string, name: string, isWindows: boolean): string {
  const sep = isWindows ? "\\" : "/";
  if (base.endsWith(sep)) return base + name;
  return base + sep + name;
}

function parentPath(path: string, isWindows: boolean): string {
  const sep = isWindows ? "\\" : "/";
  const parts = path.split(sep).filter(Boolean);
  if (parts.length <= 1) return isWindows ? parts[0] + sep : "/";
  parts.pop();
  const result = parts.join(sep);
  return isWindows ? result + sep : "/" + result;
}

function pathSegments(
  path: string,
  isWindows: boolean
): { label: string; path: string }[] {
  const sep = isWindows ? "\\" : "/";
  const parts = path.split(sep).filter(Boolean);
  const segments: { label: string; path: string }[] = [];

  if (!isWindows) {
    segments.push({ label: "/", path: "/" });
  }

  let accumulated = isWindows ? "" : "/";
  for (const part of parts) {
    accumulated = isWindows
      ? accumulated
        ? accumulated + part + "\\"
        : part + "\\"
      : accumulated + part + "/";
    segments.push({ label: part, path: accumulated });
  }
  return segments;
}

export default function FileBrowserPage() {
  const agents = useAgentStore((s) => s.agents);
  const selectedAgentId = useAgentStore((s) => s.selectedAgentId);
  const agent = agents.find((a) => a.id === selectedAgentId);
  const results = useTaskResultStore((s) => s.results);

  const [cwd, setCwd] = useState("");
  const [files, setFiles] = useState<FileEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const pendingTaskId = useRef<string | null>(null);
  const pendingAction = useRef<"list" | "pwd">("pwd");

  const isWindows = agent?.os?.toLowerCase().includes("windows") ?? false;

  const sendListCommand = useCallback(
    async (path?: string) => {
      if (!agent) return;
      setLoading(true);
      setError("");
      try {
        const target = path || cwd || ".";
        const cmd = "shell";
        const args = isWindows
          ? `dir "${target}"`
          : `ls -la "${target}"`;
        const res = await taskService.create(agent.id, cmd, args);
        pendingTaskId.current = res.id;
        pendingAction.current = "list";
      } catch (err: any) {
        setError(err.message);
        setLoading(false);
      }
    },
    [agent, cwd, isWindows]
  );

  const sendPwdCommand = useCallback(async () => {
    if (!agent) return;
    setLoading(true);
    try {
      const res = await taskService.create(agent.id, "pwd");
      pendingTaskId.current = res.id;
      pendingAction.current = "pwd";
    } catch (err: any) {
      setError(err.message);
      setLoading(false);
    }
  }, [agent]);

  useEffect(() => {
    if (agent && !cwd) {
      sendPwdCommand();
    }
  }, [agent, cwd, sendPwdCommand]);

  useEffect(() => {
    if (!pendingTaskId.current) return;
    const result = results.find((r) => r.task_id === pendingTaskId.current);
    if (!result) return;

    const output = result.decoded || "";
    pendingTaskId.current = null;

    if (pendingAction.current === "pwd") {
      const dir = output.trim();
      setCwd(dir);
      sendListCommand(dir);
    } else {
      const parsed = isWindows
        ? parseWindowsDir(output)
        : parseLinuxLs(output);
      setFiles(parsed);
      setLoading(false);
    }
  }, [results, isWindows, sendListCommand]);

  const navigateTo = (path: string) => {
    setCwd(path);
    sendListCommand(path);
  };

  const handleDownload = async (entry: FileEntry) => {
    if (!agent) return;
    const fullPath = joinPath(cwd, entry.name, isWindows);
    try {
      await taskService.create(agent.id, "download", fullPath);
    } catch (err: any) {
      console.error("Download:", err);
    }
  };

  const handleUpload = async () => {
    if (!agent) return;
    const input = document.createElement("input");
    input.type = "file";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      const remotePath = joinPath(cwd, file.name, isWindows);
      try {
        const buf = await file.arrayBuffer();
        const bytes = new Uint8Array(buf);
        let binary = "";
        for (let i = 0; i < bytes.length; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        const b64Data = btoa(binary);
        await taskService.create(agent.id, "upload", `${remotePath}\n${b64Data}`);
        setTimeout(() => sendListCommand(), 2000);
      } catch (err: any) {
        setError(`Upload failed: ${err.message}`);
      }
    };
    input.click();
  };

  if (!agent) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-apex-muted py-32">
        <Monitor className="w-12 h-12 mb-4 opacity-30" />
        <p className="text-sm font-medium">No agent selected</p>
        <p className="text-xs mt-1">
          Select an agent from the Agents page to browse files.
        </p>
      </div>
    );
  }

  const segments = cwd ? pathSegments(cwd, isWindows) : [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-apex-text">
          File Browser
          <span className="ml-2 text-sm font-normal text-apex-muted">
            {agent.hostname}
          </span>
        </h2>
        <div className="flex items-center gap-1">
          <button
            onClick={() => navigateTo(parentPath(cwd, isWindows))}
            disabled={loading}
            className="apex-btn-ghost p-2"
            title="Go up"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <button
            onClick={() => sendListCommand()}
            disabled={loading}
            className="apex-btn-ghost p-2"
            title="Refresh"
          >
            <RefreshCw
              className={`w-4 h-4 ${loading ? "animate-spin" : ""}`}
            />
          </button>
          <button
            onClick={handleUpload}
            className="apex-btn-ghost p-2"
            title="Upload"
          >
            <Upload className="w-4 h-4" />
          </button>
        </div>
      </div>

      {cwd && (
        <div className="apex-card px-4 py-2.5 flex items-center gap-1 text-sm overflow-x-auto">
          {segments.map((seg, i) => (
            <span key={i} className="flex items-center gap-1 shrink-0">
              {i > 0 && (
                <ChevronRight className="w-3 h-3 text-apex-muted" />
              )}
              <button
                onClick={() => navigateTo(seg.path)}
                className="text-apex-muted hover:text-apex-accent font-mono transition-colors"
              >
                {seg.label}
              </button>
            </span>
          ))}
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 text-xs text-apex-danger bg-apex-danger/10 px-3 py-2 rounded">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          {error}
        </div>
      )}

      {loading && files.length === 0 ? (
        <div className="apex-card flex items-center justify-center py-16">
          <Loader2 className="w-6 h-6 text-apex-muted animate-spin" />
        </div>
      ) : (
        <div className="apex-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-apex-border text-xs text-apex-muted uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-medium">Name</th>
                <th className="text-left px-4 py-3 font-medium w-24">Size</th>
                <th className="text-left px-4 py-3 font-medium w-40">
                  Modified
                </th>
                <th className="text-left px-4 py-3 font-medium w-28">
                  Permissions
                </th>
                <th className="w-10"></th>
              </tr>
            </thead>
            <tbody>
              {files.length === 0 && !loading ? (
                <tr>
                  <td
                    colSpan={5}
                    className="px-4 py-8 text-center text-apex-muted text-xs"
                  >
                    Directory is empty or awaiting response.
                  </td>
                </tr>
              ) : (
                files
                  .sort((a, b) => {
                    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
                    return a.name.localeCompare(b.name);
                  })
                  .map((entry) => (
                    <tr
                      key={entry.name}
                      className="border-b border-apex-border/50 hover:bg-apex-hover transition-colors"
                    >
                      <td className="px-4 py-2.5">
                        <button
                          onClick={() => {
                            if (entry.isDir) {
                              navigateTo(
                                joinPath(cwd, entry.name, isWindows)
                              );
                            }
                          }}
                          className={`flex items-center gap-2 ${
                            entry.isDir
                              ? "text-apex-accent hover:underline cursor-pointer"
                              : "text-apex-text cursor-default"
                          }`}
                        >
                          {entry.isDir ? (
                            <Folder className="w-4 h-4 shrink-0 text-apex-accent" />
                          ) : (
                            <File className="w-4 h-4 shrink-0 text-apex-muted" />
                          )}
                          <span className="font-mono text-xs">
                            {entry.name}
                          </span>
                        </button>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-apex-muted font-mono">
                        {entry.size}
                      </td>
                      <td className="px-4 py-2.5 text-xs text-apex-muted">
                        {entry.modified}
                      </td>
                      <td className="px-4 py-2.5 text-xs text-apex-muted font-mono">
                        {entry.permissions}
                      </td>
                      <td className="px-4 py-2.5">
                        {!entry.isDir && (
                          <button
                            onClick={() => handleDownload(entry)}
                            className="p-1.5 rounded text-apex-muted hover:text-apex-accent hover:bg-apex-accent/10 transition-colors"
                            title="Download"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
