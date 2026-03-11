import { create } from "zustand";

export type RiskLevel = "critical" | "high" | "medium" | "low" | "safe";

export interface OpsecRule {
  pattern: string;
  riskLevel: RiskLevel;
  description: string;
  alternative: string;
}

// OPSEC rules database: commands that are highly signatured or
// commonly flagged by EDR/SIEM solutions
export const OPSEC_RULES: OpsecRule[] = [
  { pattern: "whoami", riskLevel: "high", description: "Commonly logged and flagged by EDR", alternative: "Use token lookup via API or 'shell echo %USERNAME%'" },
  { pattern: "whoami /all", riskLevel: "critical", description: "Almost always triggers SOC alerts", alternative: "Query tokens programmatically" },
  { pattern: "net user", riskLevel: "high", description: "User enumeration triggers alerts", alternative: "Use LDAP queries or WMI" },
  { pattern: "net group", riskLevel: "high", description: "Group enumeration is monitored", alternative: "Use LDAP queries" },
  { pattern: "net localgroup administrators", riskLevel: "critical", description: "Admin group enum is a key indicator of compromise", alternative: "Token privilege check" },
  { pattern: "ipconfig", riskLevel: "medium", description: "Common recon command, often logged", alternative: "Use WMI or direct API calls" },
  { pattern: "systeminfo", riskLevel: "high", description: "System enumeration command frequently flagged", alternative: "Query specific registry keys" },
  { pattern: "tasklist", riskLevel: "medium", description: "Process listing is monitored", alternative: "Use NtQuerySystemInformation via BOF" },
  { pattern: "netstat", riskLevel: "medium", description: "Connection enumeration may be logged", alternative: "Use GetTcpTable API via BOF" },
  { pattern: "mimikatz", riskLevel: "critical", description: "Extremely signatured credential dumping tool", alternative: "Use custom BOFs or direct LSASS access" },
  { pattern: "hashdump", riskLevel: "critical", description: "Credential dumping triggers EDR", alternative: "Use in-memory techniques with sleep obfuscation" },
  { pattern: "powershell", riskLevel: "high", description: "PowerShell execution heavily monitored (ScriptBlock logging)", alternative: "Use unmanaged PowerShell or BOF" },
  { pattern: "cmd.exe", riskLevel: "medium", description: "Command shell spawning may trigger behavioral detection", alternative: "Use direct API calls via BOF" },
  { pattern: "reg query", riskLevel: "medium", description: "Registry queries can be audited", alternative: "Direct registry API via BOF" },
  { pattern: "sc query", riskLevel: "medium", description: "Service enumeration is logged", alternative: "WMI query or API-based approach" },
  { pattern: "wmic", riskLevel: "medium", description: "WMI command-line tool is monitored", alternative: "Use COM-based WMI directly" },
  { pattern: "certutil", riskLevel: "critical", description: "certutil for download/encode is a known LOLBin", alternative: "Use custom download via HTTP API" },
  { pattern: "bitsadmin", riskLevel: "high", description: "BITS transfer is a known persistence/download technique", alternative: "Direct HTTP download" },
  { pattern: "schtasks", riskLevel: "high", description: "Scheduled task creation is heavily monitored", alternative: "COM-based task scheduler API" },
];

export interface OpsecWarning {
  id: string;
  command: string;
  rule: OpsecRule;
  timestamp: Date;
  acknowledged: boolean;
}

interface OpsecState {
  warnings: OpsecWarning[];
  checkCommand: (command: string) => OpsecWarning | null;
  acknowledgeWarning: (id: string) => void;
  clearWarnings: () => void;
}

let warningCounter = 0;

export const useOpsecStore = create<OpsecState>((set, get) => ({
  warnings: [],

  checkCommand: (command: string) => {
    const cmdLower = command.toLowerCase().trim();
    const matchedRule = OPSEC_RULES.find((rule) =>
      cmdLower.startsWith(rule.pattern) || cmdLower.includes(rule.pattern)
    );

    if (!matchedRule) return null;

    const warning: OpsecWarning = {
      id: `opsec-${++warningCounter}`,
      command,
      rule: matchedRule,
      timestamp: new Date(),
      acknowledged: false,
    };

    set((state) => ({ warnings: [warning, ...state.warnings].slice(0, 100) }));
    return warning;
  },

  acknowledgeWarning: (id: string) =>
    set((state) => ({
      warnings: state.warnings.map((w) =>
        w.id === id ? { ...w, acknowledged: true } : w
      ),
    })),

  clearWarnings: () => set({ warnings: [] }),
}));

export function riskColor(level: RiskLevel): string {
  switch (level) {
    case "critical": return "text-red-500 bg-red-500/15";
    case "high": return "text-orange-400 bg-orange-400/15";
    case "medium": return "text-yellow-400 bg-yellow-400/15";
    case "low": return "text-blue-400 bg-blue-400/15";
    case "safe": return "text-apex-accent bg-apex-accent/15";
  }
}
