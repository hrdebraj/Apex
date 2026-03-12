import { create } from "zustand";

export interface Listener {
  id: string;
  name: string;
  protocol: "http" | "https" | "mtls" | "dns" | "tcp" | "smb";
  bindAddress: string;
  bindPort: number;
  status: "active" | "inactive" | "error";
  config: Record<string, string>;
  createdAt: string;
}

interface ListenerState {
  listeners: Listener[];

  setListeners: (listeners: Listener[]) => void;
  addListener: (listener: Listener) => void;
  updateListener: (id: string, updates: Partial<Listener>) => void;
  removeListener: (id: string) => void;
}

export const useListenerStore = create<ListenerState>((set) => ({
  listeners: [],

  setListeners: (listeners) => set({ listeners }),

  addListener: (listener) =>
    set((state) => ({ listeners: [...state.listeners, listener] })),

  updateListener: (id, updates) =>
    set((state) => ({
      listeners: state.listeners.map((l) =>
        l.id === id ? { ...l, ...updates } : l
      ),
    })),

  removeListener: (id) =>
    set((state) => ({
      listeners: state.listeners.filter((l) => l.id !== id),
    })),
}));
