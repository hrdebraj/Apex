use std::collections::HashMap;
use std::sync::Arc;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[derive(Serialize)]
pub struct SystemInfo {
    pub os: String,
    pub arch: String,
    pub hostname: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MtlsResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

pub struct MtlsState {
    pub client: Arc<Mutex<Option<reqwest::Client>>>,
}

impl Default for MtlsState {
    fn default() -> Self {
        Self {
            client: Arc::new(Mutex::new(None)),
        }
    }
}

#[tauri::command]
pub fn greet(name: &str) -> String {
    format!("Welcome to Apex, {}!", name)
}

#[tauri::command]
pub fn get_system_info() -> SystemInfo {
    SystemInfo {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        hostname: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
    }
}

#[tauri::command]
pub async fn load_mtls_cert(
    state: tauri::State<'_, MtlsState>,
    cert_pem: String,
    key_pem: String,
) -> Result<String, String> {
    let combined = format!("{}\n{}", cert_pem.trim(), key_pem.trim());
    let identity = reqwest::Identity::from_pem(combined.as_bytes())
        .map_err(|e| format!("Invalid certificate/key: {}", e))?;

    let client = reqwest::Client::builder()
        .identity(identity)
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| format!("Failed to create mTLS client: {}", e))?;

    *state.client.lock().await = Some(client);
    Ok("mTLS client configured".to_string())
}

#[tauri::command]
pub async fn clear_mtls(state: tauri::State<'_, MtlsState>) -> Result<(), String> {
    *state.client.lock().await = None;
    Ok(())
}

#[tauri::command]
pub async fn is_mtls_active(state: tauri::State<'_, MtlsState>) -> Result<bool, String> {
    Ok(state.client.lock().await.is_some())
}

#[tauri::command]
pub async fn mtls_fetch(
    state: tauri::State<'_, MtlsState>,
    method: String,
    url: String,
    headers: HashMap<String, String>,
    body: Option<String>,
) -> Result<MtlsResponse, String> {
    let guard = state.client.lock().await;
    let client = guard.as_ref().ok_or("mTLS not configured — load certificate first")?;

    let mut req = match method.to_uppercase().as_str() {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "DELETE" => client.delete(&url),
        "PUT" => client.put(&url),
        "PATCH" => client.patch(&url),
        _ => return Err(format!("Unsupported HTTP method: {}", method)),
    };

    for (key, val) in &headers {
        req = req.header(key.as_str(), val.as_str());
    }

    if let Some(b) = body {
        req = req.header("Content-Type", "application/json");
        req = req.body(b);
    }

    let resp = req.send().await.map_err(|e| format!("mTLS request failed: {}", e))?;
    let status = resp.status().as_u16();
    let resp_headers: HashMap<String, String> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let resp_body = resp.text().await.map_err(|e| format!("Read response: {}", e))?;

    Ok(MtlsResponse {
        status,
        headers: resp_headers,
        body: resp_body,
    })
}

#[tauri::command]
pub async fn mtls_sse_connect(
    state: tauri::State<'_, MtlsState>,
    app: tauri::AppHandle,
    url: String,
    token: String,
) -> Result<(), String> {
    use tauri::Emitter;

    let guard = state.client.lock().await;
    let client = guard.as_ref().ok_or("mTLS not configured")?.clone();
    drop(guard);

    let full_url = if token.is_empty() {
        url
    } else {
        format!("{}?token={}", url, token)
    };

    tauri::async_runtime::spawn(async move {
        loop {
            let resp = match client.get(&full_url).send().await {
                Ok(r) => r,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    continue;
                }
            };

            let mut stream = resp.bytes_stream();
            let mut buffer = String::new();

            while let Some(chunk) = stream.next().await {
                let chunk = match chunk {
                    Ok(c) => c,
                    Err(_) => break,
                };
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                let lines: Vec<&str> = buffer.split('\n').collect();
                let last = lines.last().cloned().unwrap_or("");
                let complete_lines = &lines[..lines.len() - 1];

                let mut event_type = String::new();
                for line in complete_lines {
                    if let Some(t) = line.strip_prefix("event: ") {
                        event_type = t.trim().to_string();
                    } else if let Some(d) = line.strip_prefix("data: ") {
                        if !event_type.is_empty() {
                            if let Ok(data) = serde_json::from_str::<serde_json::Value>(d.trim()) {
                                let payload = serde_json::json!({
                                    "type": event_type,
                                    "data": data,
                                });
                                let _ = app.emit("mtls-sse-event", payload);
                            }
                            event_type.clear();
                        }
                    }
                }
                buffer = last.to_string();
            }

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    });

    Ok(())
}
