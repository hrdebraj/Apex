import { create } from "zustand";
import { persist } from "zustand/middleware";

export interface TerminalLine {
  type: "input" | "output" | "error" | "info" | "warning";
  text: string;
  timestamp: string;
}

interface TerminalSession {
  lines: TerminalLine[];
  cmdHistory: string[];
}

interface TerminalState {
  // Per-agent sessions: agentId -> { lines, cmdHistory }
  sessions: Record<string, TerminalSession>;
  // Agent IDs that have been opened (to show tabs/selector)
  openedAgentIds: string[];

  getSession: (agentId: string) => TerminalSession;
  addLine: (agentId: string, line: Omit<TerminalLine, "timestamp">) => void;
  addCmdToHistory: (agentId: string, cmd: string) => void;
  clearSession: (agentId: string) => void;
  openAgent: (agentId: string) => void;
}

const defaultSession = (): TerminalSession => ({
  lines: [
    { type: "info", text: "Apex Terminal -- Type 'help' for commands.", timestamp: new Date().toISOString() },
  ],
  cmdHistory: [],
});

export const useTerminalStore = create<TerminalState>()(
  persist(
    (set, get) => ({
      sessions: {},
      openedAgentIds: [],

      getSession: (agentId) => {
        const s = get().sessions[agentId];
        return s || defaultSession();
      },

      addLine: (agentId, line) =>
        set((state) => {
          const sess = state.sessions[agentId] || defaultSession();
          const updated = {
            ...sess,
            lines: [
              ...sess.lines,
              { ...line, timestamp: new Date().toISOString() },
            ],
          };
          return {
            sessions: { ...state.sessions, [agentId]: updated },
            openedAgentIds: state.openedAgentIds.includes(agentId)
              ? state.openedAgentIds
              : [...state.openedAgentIds, agentId],
          };
        }),

      addCmdToHistory: (agentId, cmd) =>
        set((state) => {
          const sess = state.sessions[agentId] || defaultSession();
          const newHistory = [cmd, ...sess.cmdHistory.filter((c) => c !== cmd)].slice(0, 100);
          return {
            sessions: {
              ...state.sessions,
              [agentId]: { ...sess, cmdHistory: newHistory },
            },
          };
        }),

      clearSession: (agentId) =>
        set((state) => ({
          sessions: {
            ...state.sessions,
            [agentId]: defaultSession(),
          },
        })),

      openAgent: (agentId) =>
        set((state) => {
          if (state.openedAgentIds.includes(agentId)) return state;
          const sess = state.sessions[agentId] || defaultSession();
          return {
            sessions: { ...state.sessions, [agentId]: sess },
            openedAgentIds: [...state.openedAgentIds, agentId],
          };
        }),
    }),
    { name: "apex-terminal", partialize: (s) => ({ sessions: s.sessions, openedAgentIds: s.openedAgentIds }) }
  )
);
