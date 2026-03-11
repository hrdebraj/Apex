import { apiClient } from "./api";

interface LoginResponse {
  token: string;
  operator: {
    id: string;
    username: string;
    role: "admin" | "operator" | "readonly";
  };
}

interface OperatorResponse {
  id: string;
  username: string;
  role: string;
}

export const authService = {
  login: (username: string, password: string) =>
    apiClient.post<LoginResponse>("/api/auth/login", { username, password }),

  logout: () =>
    apiClient.post<void>("/api/auth/logout"),

  me: () =>
    apiClient.get<OperatorResponse>("/api/auth/me"),

  createOperator: (username: string, password: string, role: string) =>
    apiClient.post<OperatorResponse>("/api/operators", { username, password, role }),
};
