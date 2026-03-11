import { apiClient } from "./api";

export interface TaskResponse {
  id: string;
  agent_id: string;
  operator_id: string;
  command: string;
  status: string;
  created_at: string;
  completed_at?: string;
}

export const taskService = {
  create: (agentId: string, command: string, args?: string) =>
    apiClient.post<TaskResponse>(`/api/agents/${agentId}/tasks`, {
      command,
      arguments: args,
    }),

  listByAgent: (agentId: string) =>
    apiClient.get<TaskResponse[]>(`/api/agents/${agentId}/tasks`),
};
