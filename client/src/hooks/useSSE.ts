import { useEffect, useRef } from "react";
import { apiClient } from "../services/api";
import { useAuthStore } from "../stores/authStore";
import { useAgentStore } from "../stores/agentStore";
import { useTaskResultStore } from "../stores/taskResultStore";

export function useSSE() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const addAgent = useAgentStore((s) => s.addAgent);
  const updateAgent = useAgentStore((s) => s.updateAgent);
  const addTaskResult = useTaskResultStore((s) => s.addResult);
  const esRef = useRef<{ close: () => void } | null>(null);

  useEffect(() => {
    if (!isAuthenticated) return;

    const es = apiClient.connectSSE((type, data) => {
      // SSE payload: Event{ type, data: AgentEvent{ type, agent_id, data? } }
      const agentEvent = data?.data; // unwrap Event → AgentEvent
      switch (type) {
        case "agent:registered":
          if (agentEvent?.data) addAgent(agentEvent.data);
          break;
        case "agent:checked_in":
          if (agentEvent?.agent_id) {
            updateAgent(agentEvent.agent_id, {
              lastSeen: new Date().toISOString(),
              alive: true,
            });
          }
          break;
        case "agent:task_result": {
          const tr = agentEvent?.data;
          if (tr) {
            addTaskResult({
              task_id: tr.task_id,
              agent_id: tr.agent_id,
              output: typeof tr.output === "string" ? tr.output : "",
              success: tr.success,
              error: tr.error,
            });
          }
          break;
        }
      }
    });

    esRef.current = es;

    return () => {
      es.close();
      esRef.current = null;
    };
  }, [isAuthenticated, addAgent, updateAgent, addTaskResult]);
}
