import { apiClient } from "./api";

export interface AgentResponse {
  id: string;
  hostname: string;
  username: string;
  os: string;
  arch: string;
  pid: number;
  process_name: string;
  internal_ip: string;
  external_ip: string;
  sleep: number;
  jitter: number;
  listener_id: string;
  first_seen: string;
  last_seen: string;
  alive: boolean;
}

export const agentService = {
  list: () =>
    apiClient.get<AgentResponse[]>("/api/agents"),

  get: (id: string) =>
    apiClient.get<AgentResponse>(`/api/agents/${id}`),

  remove: (id: string) =>
    apiClient.delete<void>(`/api/agents/${id}`),
};
