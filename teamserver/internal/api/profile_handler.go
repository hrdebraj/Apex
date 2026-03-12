package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"apex/teamserver/internal/profile"
)

type ProfileHandler struct {
	profileDir string
}

func NewProfileHandler(profileDir string) *ProfileHandler {
	os.MkdirAll(profileDir, 0755)
	return &ProfileHandler{profileDir: profileDir}
}

type profileDTO struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Sleep       int      `json:"sleep"`
	Jitter      int      `json:"jitter"`
	GetURIs     []string `json:"get_uris"`
	PostURIs    []string `json:"post_uris"`
	UserAgents  []string `json:"user_agents"`
}

func (h *ProfileHandler) List(w http.ResponseWriter, _ *http.Request) {
	entries, err := os.ReadDir(h.profileDir)
	if err != nil {
		writeJSON(w, http.StatusOK, []profileDTO{})
		return
	}

	var profiles []profileDTO
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		p, err := profile.Load(filepath.Join(h.profileDir, entry.Name()))
		if err != nil {
			continue
		}
		profiles = append(profiles, profileToDTO(p))
	}

	writeJSON(w, http.StatusOK, profiles)
}

func (h *ProfileHandler) Get(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	path := filepath.Join(h.profileDir, name+".yaml")

	p, err := profile.Load(path)
	if err != nil {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}

	writeJSON(w, http.StatusOK, profileToDTO(p))
}

func (h *ProfileHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	file, header, err := r.FormFile("profile")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing 'profile' file field")
		return
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if ext != ".yaml" && ext != ".yml" {
		writeError(w, http.StatusBadRequest, "only .yaml or .yml files accepted")
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, 2<<20))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read failed")
		return
	}

	savePath := filepath.Join(h.profileDir, header.Filename)
	if err := os.WriteFile(savePath, data, 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "save failed: "+err.Error())
		return
	}

	p, err := profile.Load(savePath)
	if err != nil {
		os.Remove(savePath)
		writeError(w, http.StatusBadRequest, "invalid profile YAML: "+err.Error())
		return
	}

	log.Info().Str("name", p.Name).Str("file", header.Filename).Msg("Profile uploaded")
	writeJSON(w, http.StatusOK, profileToDTO(p))
}

func (h *ProfileHandler) Delete(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "missing profile name")
		return
	}

	path := filepath.Join(h.profileDir, name+".yaml")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = filepath.Join(h.profileDir, name+".yml")
	}

	if err := os.Remove(path); err != nil {
		writeError(w, http.StatusNotFound, "profile not found")
		return
	}

	log.Info().Str("name", name).Msg("Profile deleted")
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func profileToDTO(p *profile.MalleableProfile) profileDTO {
	return profileDTO{
		Name:        p.Name,
		Description: p.Description,
		Sleep:       p.Sleep.Interval,
		Jitter:      p.Sleep.Jitter,
		GetURIs:     p.HTTP.Get.URI,
		PostURIs:    p.HTTP.Post.URI,
		UserAgents:  p.UserAgents,
	}
}
