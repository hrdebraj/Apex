import { apiClient } from "./api";

export type OutputFormat = "exe" | "dll" | "shellcode" | "service_exe";
export type SleepMethod = "none" | "ekko" | "foliage";
export type EncryptionMethod = "aes256" | "chacha20";

export interface GeneratePayloadRequest {
  output_format: OutputFormat;
  listener_id: string;
  callback_host?: string;
  callback_port?: number;
  profile_name: string;
  sleep_obfuscation: boolean;
  sleep_method: SleepMethod;
  encrypted_shellcode: boolean;
  encryption_method: EncryptionMethod;
  unhook_ntdll: boolean;
  etw_patch: boolean;
  amsi_patch: boolean;
  hardware_breakpoint: boolean;
  byovd?: boolean;
  bof_ids?: string[];
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
};
