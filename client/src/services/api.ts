import { useAuthStore } from "../stores/authStore";

const getBaseURL = () => {
  const addr = useAuthStore.getState().serverAddr;
  // In development, the team server HTTP API runs on this address
  // Tauri desktop will connect to the configured server
  if (addr.startsWith("http")) return addr;
  return `http://${addr}`;
};

class ApiClient {
  private getHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    const token = useAuthStore.getState().token;
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }
    return headers;
  }

  async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${getBaseURL()}${path}`;
    const res = await fetch(url, {
      method,
      headers: this.getHeaders(),
      body: body ? JSON.stringify(body) : undefined,
    });

    if (res.status === 401) {
      useAuthStore.getState().logout();
      throw new Error("Session expired");
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    return res.json();
  }

  get<T>(path: string) {
    return this.request<T>("GET", path);
  }

  post<T>(path: string, body?: unknown) {
    return this.request<T>("POST", path, body);
  }

  async postForm<T>(path: string, formData: FormData): Promise<T> {
    const url = `${getBaseURL()}${path}`;
    const headers: Record<string, string> = {};
    const token = useAuthStore.getState().token;
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: formData,
    });
    if (res.status === 401) {
      useAuthStore.getState().logout();
      throw new Error("Session expired");
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }

  delete<T>(path: string) {
    return this.request<T>("DELETE", path);
  }

  connectSSE(onEvent: (type: string, data: any) => void): EventSource {
    const token = useAuthStore.getState().token;
    const url = token ? `${getBaseURL()}/api/events?token=${encodeURIComponent(token)}` : `${getBaseURL()}/api/events`;
    const es = new EventSource(url);

    es.addEventListener("connected", () => {
      console.log("[SSE] Connected to team server events");
    });

    es.addEventListener("agent:registered", (e) => {
      onEvent("agent:registered", JSON.parse(e.data));
    });

    es.addEventListener("agent:checked_in", (e) => {
      onEvent("agent:checked_in", JSON.parse(e.data));
    });

    es.addEventListener("agent:disconnected", (e) => {
      onEvent("agent:disconnected", JSON.parse(e.data));
    });

    es.addEventListener("agent:task_result", (e) => {
      onEvent("agent:task_result", JSON.parse(e.data));
    });

    es.onerror = () => {
      console.warn("[SSE] Connection lost, reconnecting...");
    };

    return es;
  }
}

export const apiClient = new ApiClient();
