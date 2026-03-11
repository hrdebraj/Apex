// Comprehensive MITRE ATT&CK technique database for C2 operations.
// Covers all 14 tactics with techniques relevant to red team / adversary simulation.

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
}

export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {

  // ─── Reconnaissance ──────────────────────────────────────────
  "T1595": { id: "T1595", name: "Active Scanning", tactic: "Reconnaissance", description: "Scanning target infrastructure for vulnerabilities" },
  "T1592": { id: "T1592", name: "Gather Victim Host Information", tactic: "Reconnaissance", description: "Gathering info about target hosts" },
  "T1589": { id: "T1589", name: "Gather Victim Identity Information", tactic: "Reconnaissance", description: "Gathering credentials, emails, names" },
  "T1590": { id: "T1590", name: "Gather Victim Network Information", tactic: "Reconnaissance", description: "Gathering network topology, DNS, IP ranges" },

  // ─── Resource Development ────────────────────────────────────
  "T1583": { id: "T1583", name: "Acquire Infrastructure", tactic: "Resource Development", description: "Acquiring servers, domains, VPS for C2" },
  "T1587.001": { id: "T1587.001", name: "Develop Capabilities: Malware", tactic: "Resource Development", description: "Developing custom implants/agents" },
  "T1588.002": { id: "T1588.002", name: "Obtain Capabilities: Tool", tactic: "Resource Development", description: "Obtaining offensive tools (C2 frameworks, BOFs)" },
  "T1608": { id: "T1608", name: "Stage Capabilities", tactic: "Resource Development", description: "Staging payloads on infrastructure" },

  // ─── Initial Access ──────────────────────────────────────────
  "T1566.001": { id: "T1566.001", name: "Phishing: Spearphishing Attachment", tactic: "Initial Access", description: "Delivering payload via email attachment" },
  "T1566.002": { id: "T1566.002", name: "Phishing: Spearphishing Link", tactic: "Initial Access", description: "Delivering payload via malicious link" },
  "T1190": { id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access", description: "Exploiting web apps, VPNs, etc." },
  "T1133": { id: "T1133", name: "External Remote Services", tactic: "Initial Access", description: "Access via VPN, RDP, SSH" },
  "T1195": { id: "T1195", name: "Supply Chain Compromise", tactic: "Initial Access", description: "Compromising software supply chain" },
  "T1199": { id: "T1199", name: "Trusted Relationship", tactic: "Initial Access", description: "Abusing trust between orgs" },

  // ─── Execution ───────────────────────────────────────────────
  "T1059.001": { id: "T1059.001", name: "PowerShell", tactic: "Execution", description: "PowerShell command or script execution" },
  "T1059.003": { id: "T1059.003", name: "Windows Command Shell", tactic: "Execution", description: "cmd.exe command execution" },
  "T1059.004": { id: "T1059.004", name: "Unix Shell", tactic: "Execution", description: "Bash/sh command execution" },
  "T1059.005": { id: "T1059.005", name: "Visual Basic", tactic: "Execution", description: "VBScript/VBA macro execution" },
  "T1059.006": { id: "T1059.006", name: "Python", tactic: "Execution", description: "Python script execution" },
  "T1059.007": { id: "T1059.007", name: "JavaScript", tactic: "Execution", description: "JScript/Node.js execution" },
  "T1106": { id: "T1106", name: "Native API", tactic: "Execution", description: "Direct Windows API calls (NtCreateThread, etc.)" },
  "T1053.005": { id: "T1053.005", name: "Scheduled Task", tactic: "Execution", description: "Execute via schtasks / Task Scheduler" },
  "T1047": { id: "T1047", name: "Windows Management Instrumentation", tactic: "Execution", description: "Execute via WMI/WMIC" },
  "T1204.002": { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution", description: "User runs a malicious file" },
  "T1569.002": { id: "T1569.002", name: "Service Execution", tactic: "Execution", description: "Execute via Windows service creation" },

  // ─── Persistence ─────────────────────────────────────────────
  "T1547.001": { id: "T1547.001", name: "Registry Run Keys", tactic: "Persistence", description: "Persistence via HKCU/HKLM Run keys" },
  "T1053.005P": { id: "T1053.005", name: "Scheduled Task (Persistence)", tactic: "Persistence", description: "Persist via scheduled task" },
  "T1543.003": { id: "T1543.003", name: "Windows Service", tactic: "Persistence", description: "Create or modify Windows service" },
  "T1546.003": { id: "T1546.003", name: "WMI Event Subscription", tactic: "Persistence", description: "Persist via WMI event consumer" },
  "T1197": { id: "T1197", name: "BITS Jobs", tactic: "Persistence", description: "Persist via BITS transfer jobs" },
  "T1136": { id: "T1136", name: "Create Account", tactic: "Persistence", description: "Create local or domain account for persistence" },
  "T1078": { id: "T1078", name: "Valid Accounts", tactic: "Persistence", description: "Use compromised credentials for persistent access" },
  "T1505.003": { id: "T1505.003", name: "Web Shell", tactic: "Persistence", description: "Plant web shell for persistent access" },

  // ─── Privilege Escalation ────────────────────────────────────
  "T1134": { id: "T1134", name: "Access Token Manipulation", tactic: "Privilege Escalation", description: "Token impersonation/theft" },
  "T1134.001": { id: "T1134.001", name: "Token Impersonation/Theft", tactic: "Privilege Escalation", description: "Impersonate another user's token" },
  "T1068": { id: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation", description: "Exploit kernel or service vulnerability" },
  "T1055": { id: "T1055", name: "Process Injection", tactic: "Privilege Escalation", description: "Inject code into higher-privilege process" },
  "T1548.002": { id: "T1548.002", name: "Bypass UAC", tactic: "Privilege Escalation", description: "Bypass User Account Control" },
  "T1574.001": { id: "T1574.001", name: "DLL Search Order Hijacking", tactic: "Privilege Escalation", description: "Hijack DLL load order" },
  "T1574.002": { id: "T1574.002", name: "DLL Side-Loading", tactic: "Privilege Escalation", description: "Side-load malicious DLL into legitimate process" },

  // ─── Defense Evasion ─────────────────────────────────────────
  "T1562.001": { id: "T1562.001", name: "Disable or Modify Tools", tactic: "Defense Evasion", description: "Disabling security tools / EDR" },
  "T1562.002": { id: "T1562.002", name: "Disable Windows Event Logging", tactic: "Defense Evasion", description: "Disable or tamper with event logs" },
  "T1070.001": { id: "T1070.001", name: "Clear Windows Event Logs", tactic: "Defense Evasion", description: "Clear event logs to cover tracks" },
  "T1070.004": { id: "T1070.004", name: "File Deletion", tactic: "Defense Evasion", description: "Delete files to remove indicators" },
  "T1027": { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion", description: "Obfuscate payloads, encoding, encryption" },
  "T1027.002": { id: "T1027.002", name: "Software Packing", tactic: "Defense Evasion", description: "Pack executables to evade signatures" },
  "T1140": { id: "T1140", name: "Deobfuscate/Decode Files", tactic: "Defense Evasion", description: "Decode encoded payloads at runtime" },
  "T1055.001": { id: "T1055.001", name: "DLL Injection", tactic: "Defense Evasion", description: "Inject DLL into remote process" },
  "T1055.002": { id: "T1055.002", name: "PE Injection", tactic: "Defense Evasion", description: "Inject portable executable into process" },
  "T1055.003": { id: "T1055.003", name: "Thread Execution Hijacking", tactic: "Defense Evasion", description: "Hijack thread in remote process" },
  "T1055.004": { id: "T1055.004", name: "Asynchronous Procedure Call", tactic: "Defense Evasion", description: "APC injection for code execution" },
  "T1055.012": { id: "T1055.012", name: "Process Hollowing", tactic: "Defense Evasion", description: "Hollow out legitimate process and inject" },
  "T1218.005": { id: "T1218.005", name: "Mshta", tactic: "Defense Evasion", description: "Execute via mshta.exe (LOLBin)" },
  "T1218.010": { id: "T1218.010", name: "Regsvr32", tactic: "Defense Evasion", description: "Execute via regsvr32.exe (LOLBin)" },
  "T1218.011": { id: "T1218.011", name: "Rundll32", tactic: "Defense Evasion", description: "Execute via rundll32.exe (LOLBin)" },
  "T1036": { id: "T1036", name: "Masquerading", tactic: "Defense Evasion", description: "Disguise as legitimate file/process" },
  "T1112": { id: "T1112", name: "Modify Registry", tactic: "Defense Evasion", description: "Modify registry to hide artifacts" },
  "T1497": { id: "T1497", name: "Virtualization/Sandbox Evasion", tactic: "Defense Evasion", description: "Detect and evade sandboxes/VMs" },
  "T1620": { id: "T1620", name: "Reflective Code Loading", tactic: "Defense Evasion", description: "Load PE/DLL reflectively without touching disk" },
  "T1622": { id: "T1622", name: "Debugger Evasion", tactic: "Defense Evasion", description: "Detect and evade debugger analysis" },

  // ─── Credential Access ───────────────────────────────────────
  "T1003": { id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access", description: "Credential harvesting (LSASS, SAM, etc.)" },
  "T1003.001": { id: "T1003.001", name: "LSASS Memory", tactic: "Credential Access", description: "Dump LSASS process for credentials" },
  "T1003.002": { id: "T1003.002", name: "Security Account Manager", tactic: "Credential Access", description: "Extract hashes from SAM database" },
  "T1003.003": { id: "T1003.003", name: "NTDS", tactic: "Credential Access", description: "Extract credentials from AD NTDS.dit" },
  "T1003.006": { id: "T1003.006", name: "DCSync", tactic: "Credential Access", description: "Replicate AD credentials via DCSync" },
  "T1110": { id: "T1110", name: "Brute Force", tactic: "Credential Access", description: "Brute force authentication" },
  "T1558.003": { id: "T1558.003", name: "Kerberoasting", tactic: "Credential Access", description: "Request TGS tickets for offline cracking" },
  "T1552.001": { id: "T1552.001", name: "Credentials In Files", tactic: "Credential Access", description: "Search files for stored credentials" },
  "T1555": { id: "T1555", name: "Credentials from Password Stores", tactic: "Credential Access", description: "Extract credentials from browsers/vaults" },
  "T1557": { id: "T1557", name: "Adversary-in-the-Middle", tactic: "Credential Access", description: "Intercept authentication (LLMNR/NBNS)" },
  "T1187": { id: "T1187", name: "Forced Authentication", tactic: "Credential Access", description: "Force NTLM auth to capture hashes" },

  // ─── Discovery ───────────────────────────────────────────────
  "T1057": { id: "T1057", name: "Process Discovery", tactic: "Discovery", description: "Process listing (ps, tasklist)" },
  "T1083": { id: "T1083", name: "File and Directory Discovery", tactic: "Discovery", description: "File system enumeration (ls, dir)" },
  "T1082": { id: "T1082", name: "System Information Discovery", tactic: "Discovery", description: "System info gathering (systeminfo, uname)" },
  "T1033": { id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery", description: "User enumeration (whoami, id)" },
  "T1016": { id: "T1016", name: "System Network Configuration Discovery", tactic: "Discovery", description: "Network config (ipconfig, ifconfig)" },
  "T1049": { id: "T1049", name: "System Network Connections Discovery", tactic: "Discovery", description: "Active connections (netstat)" },
  "T1018": { id: "T1018", name: "Remote System Discovery", tactic: "Discovery", description: "Discover remote systems (net view, ping sweep)" },
  "T1087": { id: "T1087", name: "Account Discovery", tactic: "Discovery", description: "Enumerate user/admin accounts" },
  "T1087.002": { id: "T1087.002", name: "Domain Account Discovery", tactic: "Discovery", description: "Enumerate domain accounts via LDAP/net" },
  "T1069": { id: "T1069", name: "Permission Groups Discovery", tactic: "Discovery", description: "Enumerate groups (Domain Admins, etc.)" },
  "T1482": { id: "T1482", name: "Domain Trust Discovery", tactic: "Discovery", description: "Enumerate domain trusts" },
  "T1135": { id: "T1135", name: "Network Share Discovery", tactic: "Discovery", description: "Enumerate SMB shares" },
  "T1012": { id: "T1012", name: "Query Registry", tactic: "Discovery", description: "Query registry for config/software info" },
  "T1518": { id: "T1518", name: "Software Discovery", tactic: "Discovery", description: "Enumerate installed software" },
  "T1518.001": { id: "T1518.001", name: "Security Software Discovery", tactic: "Discovery", description: "Detect AV/EDR products installed" },
  "T1007": { id: "T1007", name: "System Service Discovery", tactic: "Discovery", description: "Enumerate running services" },
  "T1046": { id: "T1046", name: "Network Service Discovery", tactic: "Discovery", description: "Port scan internal network" },
  "T1010": { id: "T1010", name: "Application Window Discovery", tactic: "Discovery", description: "Enumerate visible application windows" },

  // ─── Lateral Movement ────────────────────────────────────────
  "T1021.001": { id: "T1021.001", name: "Remote Desktop Protocol", tactic: "Lateral Movement", description: "Lateral move via RDP" },
  "T1021.002": { id: "T1021.002", name: "SMB/Windows Admin Shares", tactic: "Lateral Movement", description: "Lateral move via SMB (C$, ADMIN$)" },
  "T1021.003": { id: "T1021.003", name: "DCOM", tactic: "Lateral Movement", description: "Lateral move via Distributed COM" },
  "T1021.006": { id: "T1021.006", name: "Windows Remote Management", tactic: "Lateral Movement", description: "Lateral move via WinRM/PSRemoting" },
  "T1570": { id: "T1570", name: "Lateral Tool Transfer", tactic: "Lateral Movement", description: "Transfer tools between internal systems" },
  "T1563": { id: "T1563", name: "Remote Service Session Hijacking", tactic: "Lateral Movement", description: "Hijack existing RDP/SSH sessions" },
  "T1550.002": { id: "T1550.002", name: "Pass the Hash", tactic: "Lateral Movement", description: "Authenticate using NTLM hash" },
  "T1550.003": { id: "T1550.003", name: "Pass the Ticket", tactic: "Lateral Movement", description: "Authenticate using Kerberos ticket" },

  // ─── Collection ──────────────────────────────────────────────
  "T1005": { id: "T1005", name: "Data from Local System", tactic: "Collection", description: "Collect files from target system" },
  "T1039": { id: "T1039", name: "Data from Network Shared Drive", tactic: "Collection", description: "Collect files from network shares" },
  "T1113": { id: "T1113", name: "Screen Capture", tactic: "Collection", description: "Capture screenshots" },
  "T1056.001": { id: "T1056.001", name: "Keylogging", tactic: "Collection", description: "Log keystrokes" },
  "T1560": { id: "T1560", name: "Archive Collected Data", tactic: "Collection", description: "Compress/archive data before exfil" },
  "T1115": { id: "T1115", name: "Clipboard Data", tactic: "Collection", description: "Capture clipboard contents" },
  "T1119": { id: "T1119", name: "Automated Collection", tactic: "Collection", description: "Automated data gathering scripts" },
  "T1074": { id: "T1074", name: "Data Staged", tactic: "Collection", description: "Stage collected data for exfiltration" },

  // ─── Command and Control ─────────────────────────────────────
  "T1071.001": { id: "T1071.001", name: "Web Protocols", tactic: "Command and Control", description: "HTTP/HTTPS C2 communication" },
  "T1071.004": { id: "T1071.004", name: "DNS", tactic: "Command and Control", description: "DNS-based C2 communication" },
  "T1071.002": { id: "T1071.002", name: "File Transfer Protocols", tactic: "Command and Control", description: "FTP/SFTP for C2 data transfer" },
  "T1105": { id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control", description: "Upload tools to target" },
  "T1572": { id: "T1572", name: "Protocol Tunneling", tactic: "Command and Control", description: "Tunnel C2 through legitimate protocols" },
  "T1573.001": { id: "T1573.001", name: "Encrypted Channel: Symmetric", tactic: "Command and Control", description: "AES/ChaCha20 encrypted C2 channel" },
  "T1573.002": { id: "T1573.002", name: "Encrypted Channel: Asymmetric", tactic: "Command and Control", description: "RSA/ECC encrypted C2 channel" },
  "T1090.001": { id: "T1090.001", name: "Internal Proxy", tactic: "Command and Control", description: "Route C2 through internal proxy/pivot" },
  "T1090.002": { id: "T1090.002", name: "External Proxy", tactic: "Command and Control", description: "Route C2 through external redirectors" },
  "T1102": { id: "T1102", name: "Web Service", tactic: "Command and Control", description: "Use legitimate web services for C2 (Graph API, etc.)" },
  "T1001.001": { id: "T1001.001", name: "Junk Data", tactic: "Command and Control", description: "Add junk data to C2 traffic" },
  "T1001.002": { id: "T1001.002", name: "Steganography", tactic: "Command and Control", description: "Hide C2 data in images/media" },
  "T1568": { id: "T1568", name: "Dynamic Resolution", tactic: "Command and Control", description: "Dynamically resolve C2 endpoints (DGA, fast-flux)" },
  "T1095": { id: "T1095", name: "Non-Application Layer Protocol", tactic: "Command and Control", description: "Raw TCP/UDP/ICMP for C2" },
  "T1571": { id: "T1571", name: "Non-Standard Port", tactic: "Command and Control", description: "C2 on unusual ports" },
  "T1132": { id: "T1132", name: "Data Encoding", tactic: "Command and Control", description: "Encode C2 data (base64, custom)" },
  "T1008": { id: "T1008", name: "Fallback Channels", tactic: "Command and Control", description: "Use backup C2 channels" },

  // ─── Exfiltration ────────────────────────────────────────────
  "T1041": { id: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration", description: "Exfiltrate data over existing C2" },
  "T1048": { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration", description: "Exfil via DNS, ICMP, or separate channel" },
  "T1567": { id: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration", description: "Exfil to cloud storage (S3, OneDrive, etc.)" },
  "T1029": { id: "T1029", name: "Scheduled Transfer", tactic: "Exfiltration", description: "Exfil on a schedule to blend with traffic" },
  "T1030": { id: "T1030", name: "Data Transfer Size Limits", tactic: "Exfiltration", description: "Limit transfer size to avoid detection" },

  // ─── Impact ──────────────────────────────────────────────────
  "T1486": { id: "T1486", name: "Data Encrypted for Impact", tactic: "Impact", description: "Ransomware encryption" },
  "T1489": { id: "T1489", name: "Service Stop", tactic: "Impact", description: "Stop critical services" },
  "T1490": { id: "T1490", name: "Inhibit System Recovery", tactic: "Impact", description: "Delete shadow copies, disable recovery" },
  "T1529": { id: "T1529", name: "System Shutdown/Reboot", tactic: "Impact", description: "Force system shutdown or reboot" },
  "T1531": { id: "T1531", name: "Account Access Removal", tactic: "Impact", description: "Change passwords / lock out accounts" },
};

// Comprehensive command-to-MITRE mapping for automatic tracking
export const COMMAND_TO_MITRE: Record<string, string[]> = {
  // Discovery
  "whoami":         ["T1033"],
  "id":             ["T1033"],
  "ps":             ["T1057"],
  "tasklist":       ["T1057"],
  "ls":             ["T1083"],
  "dir":            ["T1083"],
  "find":           ["T1083"],
  "cat":            ["T1005"],
  "type":           ["T1005"],
  "systeminfo":     ["T1082"],
  "uname":          ["T1082"],
  "hostname":       ["T1082"],
  "ipconfig":       ["T1016"],
  "ifconfig":       ["T1016"],
  "ip":             ["T1016"],
  "netstat":        ["T1049"],
  "ss":             ["T1049"],
  "arp":            ["T1018"],
  "ping":           ["T1018"],
  "nslookup":       ["T1018"],
  "net":            ["T1087"],
  "dsquery":        ["T1087.002"],
  "nltest":         ["T1482"],
  "reg":            ["T1012"],
  "wmic":           ["T1047", "T1082"],
  "sc":             ["T1007"],
  "nmap":           ["T1046"],

  // Execution
  "shell":          ["T1059.003"],
  "cmd":            ["T1059.003"],
  "powershell":     ["T1059.001"],
  "psh":            ["T1059.001"],
  "execute":        ["T1106"],
  "run":            ["T1106"],
  "python":         ["T1059.006"],
  "schtasks":       ["T1053.005"],

  // File operations / Collection / Exfiltration
  "download":       ["T1005", "T1041"],
  "upload":         ["T1105"],
  "screenshot":     ["T1113"],
  "keylogger":      ["T1056.001"],
  "clipboard":      ["T1115"],

  // Credential Access
  "hashdump":       ["T1003", "T1003.002"],
  "mimikatz":       ["T1003", "T1003.001"],
  "lsass":          ["T1003.001"],
  "secretsdump":    ["T1003", "T1003.003"],
  "dcsync":         ["T1003.006"],
  "kerberoast":     ["T1558.003"],
  "credentials":    ["T1555"],

  // Lateral Movement
  "psexec":         ["T1021.002", "T1569.002"],
  "wmiexec":        ["T1047", "T1021.003"],
  "winrm":          ["T1021.006"],
  "rdp":            ["T1021.001"],
  "pth":            ["T1550.002"],
  "ptt":            ["T1550.003"],
  "lateral":        ["T1570"],

  // Privilege Escalation
  "getsystem":      ["T1134", "T1134.001"],
  "token":          ["T1134"],
  "impersonate":    ["T1134.001"],
  "elevate":        ["T1068"],
  "runas":          ["T1134"],
  "bypassuac":      ["T1548.002"],

  // Defense Evasion
  "inject":         ["T1055"],
  "migrate":        ["T1055.001"],
  "hollow":         ["T1055.012"],
  "unhook":         ["T1562.001"],
  "etw":            ["T1562.002"],
  "amsi":           ["T1562.001"],
  "reflective":     ["T1620"],
  "bof":            ["T1106", "T1620"],
  "coff":           ["T1106", "T1620"],
  "sleep":          ["T1497"],

  // Persistence
  "persist":        ["T1547.001"],
  "service":        ["T1543.003"],
  "startup":        ["T1547.001"],

  // C2
  "pivot":          ["T1090.001"],
  "proxy":          ["T1090.002"],
  "tunnel":         ["T1572"],
  "link":           ["T1095"],
  "p2p":            ["T1095"],

  // Impact
  "kill":           ["T1489"],
  "shutdown":       ["T1529"],

  // LOLBins
  "certutil":       ["T1140", "T1105"],
  "bitsadmin":      ["T1197", "T1105"],
  "mshta":          ["T1218.005"],
  "regsvr32":       ["T1218.010"],
  "rundll32":       ["T1218.011"],
};

export const TACTIC_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export const TACTIC_COLORS: Record<string, string> = {
  "Reconnaissance":       "#78909c",
  "Resource Development": "#8d6e63",
  "Initial Access":       "#e57373",
  "Execution":            "#ff6b6b",
  "Persistence":          "#ffb74d",
  "Privilege Escalation": "#fd9644",
  "Defense Evasion":      "#a55eea",
  "Credential Access":    "#fc5c65",
  "Discovery":            "#4ecdc4",
  "Lateral Movement":     "#f9ca24",
  "Collection":           "#45b7d1",
  "Command and Control":  "#00d4aa",
  "Exfiltration":         "#eb3b5a",
  "Impact":               "#d63031",
};
