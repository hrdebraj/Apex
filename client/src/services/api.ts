import { fetch as tauriFetch } from "@tauri-apps/plugin-http";
import { useAuthStore } from "../stores/authStore";

const getBaseURL = () => {
  const addr = useAuthStore.getState().serverAddr;
  if (addr.startsWith("http")) return addr;
  return `https://${addr}`;
};

const FETCH_OPTS = {
  danger: { acceptInvalidCerts: true, acceptInvalidHostnames: true },
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
    const res = await tauriFetch(url, {
      method,
      headers: this.getHeaders(),
      body: body ? JSON.stringify(body) : undefined,
      ...FETCH_OPTS,
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
    const res = await tauriFetch(url, {
      method: "POST",
      headers,
      body: formData,
      ...FETCH_OPTS,
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

  connectSSE(onEvent: (type: string, data: any) => void): { close: () => void } {
    const token = useAuthStore.getState().token;
    const url = token
      ? `${getBaseURL()}/api/events?token=${encodeURIComponent(token)}`
      : `${getBaseURL()}/api/events`;

    let aborted = false;

    const connect = async () => {
      if (aborted) return;
      try {
        const res = await tauriFetch(url, { ...FETCH_OPTS });
        const reader = res.body?.getReader();
        if (!reader) return;

        const decoder = new TextDecoder();
        let buffer = "";

        while (!aborted) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop() || "";

          let eventType = "";
          for (const line of lines) {
            if (line.startsWith("event: ")) {
              eventType = line.slice(7).trim();
            } else if (line.startsWith("data: ") && eventType) {
              try {
                const data = JSON.parse(line.slice(6));
                onEvent(eventType, data);
              } catch {
                // skip malformed data
              }
              eventType = "";
            }
          }
        }
      } catch {
        // reconnect after delay
      }

      if (!aborted) {
        setTimeout(connect, 3000);
      }
    };

    connect();

    return {
      close: () => {
        aborted = true;
      },
    };
  }
}

export const apiClient = new ApiClient();
