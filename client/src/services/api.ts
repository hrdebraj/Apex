import { fetch as tauriFetch } from "@tauri-apps/plugin-http";
import { invoke } from "@tauri-apps/api/core";
import { useAuthStore } from "../stores/authStore";

const getBaseURL = () => {
  const addr = useAuthStore.getState().serverAddr;
  if (addr.startsWith("http")) return addr;
  return `https://${addr}`;
};

const FETCH_OPTS = {
  danger: { acceptInvalidCerts: true, acceptInvalidHostnames: true },
};

interface MtlsResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

async function apexFetch(
  url: string,
  method: string,
  headers: Record<string, string>,
  body?: string,
): Promise<{ status: number; ok: boolean; body: string; headers: Record<string, string> }> {
  const { mtlsEnabled } = useAuthStore.getState();

  if (mtlsEnabled) {
    const resp = await invoke<MtlsResponse>("mtls_fetch", {
      method,
      url,
      headers,
      body: body ?? null,
    });
    return {
      status: resp.status,
      ok: resp.status >= 200 && resp.status < 300,
      body: resp.body,
      headers: resp.headers,
    };
  }

  const res = await tauriFetch(url, {
    method,
    headers,
    body: body ?? undefined,
    ...FETCH_OPTS,
  });
  const resBody = await res.text();
  const resHeaders: Record<string, string> = {};
  res.headers.forEach((v, k) => { resHeaders[k] = v; });
  return {
    status: res.status,
    ok: res.ok,
    body: resBody,
    headers: resHeaders,
  };
}

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
    const res = await apexFetch(
      url,
      method,
      this.getHeaders(),
      body ? JSON.stringify(body) : undefined,
    );

    if (res.status === 401) {
      useAuthStore.getState().logout();
      throw new Error("Session expired");
    }

    if (!res.ok) {
      let errMsg = `HTTP ${res.status}`;
      try {
        const err = JSON.parse(res.body);
        errMsg = err.error || errMsg;
      } catch {}
      throw new Error(errMsg);
    }

    return JSON.parse(res.body);
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
    const { mtlsEnabled, token } = useAuthStore.getState();
    const baseUrl = getBaseURL();
    const sseUrl = `${baseUrl}/api/events`;
    const urlWithToken = token
      ? `${sseUrl}?token=${encodeURIComponent(token)}`
      : sseUrl;

    let aborted = false;

    if (mtlsEnabled) {
      invoke("mtls_sse_connect", { url: sseUrl, token: token || "" }).catch(() => {});

      let unlisten: (() => void) | null = null;
      import("@tauri-apps/api/event").then(({ listen }) => {
        listen("mtls-sse-event", (event: any) => {
          if (aborted) return;
          const payload = event.payload;
          if (payload?.type && payload?.data) {
            onEvent(payload.type, payload.data);
          }
        }).then((fn) => {
          unlisten = fn;
        });
      });

      return {
        close: () => {
          aborted = true;
          if (unlisten) unlisten();
        },
      };
    }

    const connect = async () => {
      if (aborted) return;
      try {
        const res = await tauriFetch(urlWithToken, { ...FETCH_OPTS });
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
