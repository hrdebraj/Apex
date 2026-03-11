import { create } from "zustand";

export interface TaskResult {
  task_id: string;
  agent_id: string;
  output: string; // base64
  success: boolean;
  error?: string;
}

interface TaskResultState {
  results: Array<TaskResult & { decoded?: string }>;
  addResult: (r: TaskResult) => void;
  clearResults: () => void;
}

export const useTaskResultStore = create<TaskResultState>((set) => ({
  results: [],

  addResult: (r) =>
    set((state) => {
      let decoded = "";
      try {
        decoded = atob(r.output || "");
      } catch {
        decoded = "[decode error]";
      }
      return {
        results: [
          ...state.results,
          { ...r, decoded },
        ].slice(-100),
      };
    }),

  clearResults: () => set({ results: [] }),
}));
