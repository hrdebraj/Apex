import { create } from "zustand";
import { persist } from "zustand/middleware";

interface Operator {
  id: string;
  username: string;
  role: "admin" | "operator" | "readonly";
}

interface AuthState {
  isAuthenticated: boolean;
  token: string | null;
  operator: Operator | null;
  serverAddr: string;
  mtlsEnabled: boolean;

  login: (serverAddr: string, token: string, operator: Operator) => void;
  logout: () => void;
  setServerAddr: (addr: string) => void;
  setMtls: (enabled: boolean) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      isAuthenticated: false,
      token: null,
      operator: null,
      serverAddr: "localhost:8443",
      mtlsEnabled: false,

      login: (serverAddr, token, operator) =>
        set({ isAuthenticated: true, token, operator, serverAddr }),

      logout: () =>
        set({ isAuthenticated: false, token: null, operator: null }),

      setServerAddr: (addr) => set({ serverAddr: addr }),

      setMtls: (enabled) => set({ mtlsEnabled: enabled }),
    }),
    {
      name: "apex-auth",
      partialize: (state) => ({
        serverAddr: state.serverAddr,
        token: state.token,
        operator: state.operator,
        isAuthenticated: state.isAuthenticated,
        mtlsEnabled: state.mtlsEnabled,
      }),
    }
  )
);
