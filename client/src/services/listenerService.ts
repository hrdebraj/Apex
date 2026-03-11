import { apiClient } from "./api";

export interface ListenerResponse {
  id: string;
  name: string;
  protocol: string;
  bind_address: string;
  bind_port: number;
  status: string;
  config?: Record<string, string>;
}

interface CreateListenerPayload {
  name: string;
  protocol: string;
  bind_address: string;
  bind_port: number;
  config?: Record<string, string>;
}

export const listenerService = {
  list: () =>
    apiClient.get<ListenerResponse[]>("/api/listeners"),

  get: (id: string) =>
    apiClient.get<ListenerResponse>(`/api/listeners/${id}`),

  create: (payload: CreateListenerPayload) =>
    apiClient.post<ListenerResponse>("/api/listeners", payload),

  start: (id: string) =>
    apiClient.post<ListenerResponse>(`/api/listeners/${id}/start`),

  stop: (id: string) =>
    apiClient.post<ListenerResponse>(`/api/listeners/${id}/stop`),

  remove: (id: string) =>
    apiClient.delete<void>(`/api/listeners/${id}`),
};
