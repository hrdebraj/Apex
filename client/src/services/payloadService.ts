import { apiClient } from "./api";

export type Platform = "windows" | "linux" | "macos";
export type OutputFormat = "exe" | "dll" | "shellcode" | "service_exe" | "elf" | "macho";
export type SleepMethod = "none" | "ekko" | "foliage";
export type EncryptionMethod = "aes256" | "chacha20";
export type SyscallMethod = "auto" | "hellsgate" | "halosgate";

export interface GeneratePayloadRequest {
  platform: Platform;
  output_format: OutputFormat;
  listener_id: string;
  callback_host?: string;
  callback_port?: number;
  profile_name: string;
  // Windows evasion
  sleep_obfuscation: boolean;
  sleep_method: SleepMethod;
  encrypted_shellcode: boolean;
  encryption_method: EncryptionMethod;
  unhook_ntdll: boolean;
  etw_patch: boolean;
  amsi_patch: boolean;
  hardware_breakpoint: boolean;
  indirect_syscall: boolean;
  syscall_method: SyscallMethod;
  nt_process: boolean;     // Issue #7: NtCreateUserProcess instead of CreateProcessA
  heap_encrypt: boolean;   // Issue #4: XOR-encrypt heap regions during sleep
  pe_stomp: boolean;       // PE header stomping (defeats pe-sieve/Moneta)
  pe_stomp_mode: number;   // 1=DOS-only 2=full-NT 3=sledgehammer
  pe_stomp_randomise: boolean;
  udrl: boolean;
  drip_load: boolean;
  ret_addr_spoof: boolean;
  synthetic_frames: boolean;
  block_dlls: boolean;
  arg_spoof: boolean;
  ppid_spoof: boolean;
  byovd?: boolean;
  bof_ids?: string[];
  // POSIX evasion (Linux/macOS)
  anti_debug: boolean;
  proc_mask: boolean;
  self_delete: boolean;
  env_clean: boolean;
  sandbox_check: boolean;
}

export interface GeneratePayloadResponse {
  success: boolean;
  message: string;
  payload_base64?: string;
  filename?: string;
  payload_id?: string;
  download_url?: string;
}

export const payloadService = {
  generate: (req: GeneratePayloadRequest) =>
    apiClient.post<GeneratePayloadResponse>("/api/payloads/generate", req),

  listBOFs: () =>
    apiClient.get<Array<{ id: string; name: string }>>("/api/payloads/bofs"),

  uploadBOF: async (file: File) => {
    const formData = new FormData();
    formData.append("bof", file);
    return apiClient.postForm<{ id: string; name: string; message?: string }>("/api/payloads/bofs", formData);
  },

  deleteBOF: (id: string) =>
    apiClient.delete<{ status: string }>(`/api/payloads/bofs?id=${id}`),

  getBOFData: (id: string) =>
    apiClient.get<{ data: string }>(`/api/payloads/bofs/${id}/data`),
};
