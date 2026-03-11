package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"

	"apex/teamserver/internal/profile"
)

type ProfileHandler struct {
	profileDir string
}

func NewProfileHandler(profileDir string) *ProfileHandler {
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
