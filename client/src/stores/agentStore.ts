import { create } from "zustand";

export interface Agent {
  id: string;
  hostname: string;
  username: string;
  os: string;
  arch: string;
  pid: number;
  processName: string;
  internalIp: string;
  externalIp: string;
  sleep: number;
  jitter: number;
  listenerId: string;
  firstSeen: string;
  lastSeen: string;
  alive: boolean;
}

interface AgentState {
  agents: Agent[];
  selectedAgentId: string | null;

  setAgents: (agents: Agent[]) => void;
  addAgent: (agent: Agent) => void;
  updateAgent: (id: string, updates: Partial<Agent>) => void;
  removeAgent: (id: string) => void;
  selectAgent: (id: string | null) => void;
}

export const useAgentStore = create<AgentState>((set) => ({
  agents: [],
  selectedAgentId: null,

  setAgents: (agents) => set({ agents }),

  addAgent: (agent) =>
    set((state) => ({ agents: [...state.agents, agent] })),

  updateAgent: (id, updates) =>
    set((state) => ({
      agents: state.agents.map((a) =>
        a.id === id ? { ...a, ...updates } : a
      ),
    })),

  removeAgent: (id) =>
    set((state) => ({
      agents: state.agents.filter((a) => a.id !== id),
      selectedAgentId:
        state.selectedAgentId === id ? null : state.selectedAgentId,
    })),

  selectAgent: (id) => set({ selectedAgentId: id }),
}));
