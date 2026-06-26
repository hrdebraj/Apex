mod commands;

use commands::MtlsState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_http::init())
        .manage(MtlsState::default())
        .invoke_handler(tauri::generate_handler![
            commands::greet,
            commands::get_system_info,
            commands::load_mtls_cert,
            commands::clear_mtls,
            commands::is_mtls_active,
            commands::mtls_fetch,
            commands::mtls_sse_connect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Apex client");
}
