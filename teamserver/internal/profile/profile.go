package profile

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// MalleableProfile defines how HTTP traffic is shaped to evade detection.
// Operators write YAML profiles; the HTTP listener applies them to
// transform check-in requests and task responses to look like legitimate traffic.
type MalleableProfile struct {
	Name        string       `yaml:"name"`
	Description string       `yaml:"description"`
	Sleep       SleepConfig  `yaml:"sleep"`
	HTTP        HTTPProfile  `yaml:"http"`
	UserAgents  []string     `yaml:"user_agents"`
}

type SleepConfig struct {
	Interval int `yaml:"interval"` // seconds
	Jitter   int `yaml:"jitter"`   // percentage (0-100)
}

func (s SleepConfig) Calculate() time.Duration {
	base := time.Duration(s.Interval) * time.Second
	if s.Jitter <= 0 {
		return base
	}
	jitterRange := float64(base) * (float64(s.Jitter) / 100.0)
	offset := time.Duration(rand.Float64()*jitterRange*2 - jitterRange)
	result := base + offset
	if result < time.Second {
		result = time.Second
	}
	return result
}

type HTTPProfile struct {
	Get  HTTPTransaction `yaml:"get"`
	Post HTTPTransaction `yaml:"post"`
}

type HTTPTransaction struct {
	URI     []string          `yaml:"uri"`
	Headers map[string]string `yaml:"headers"`
	Client  TransformBlock    `yaml:"client"`
	Server  TransformBlock    `yaml:"server"`
}

type TransformBlock struct {
	// How data is encoded in the request/response
	Metadata MetadataConfig `yaml:"metadata"`
	Output   OutputConfig   `yaml:"output"`
}

type MetadataConfig struct {
	Header string `yaml:"header"` // HTTP header to embed metadata in
	Prepend string `yaml:"prepend"`
	Append  string `yaml:"append"`
	Base64  bool   `yaml:"base64"`
}

type OutputConfig struct {
	Prepend     string `yaml:"prepend"`
	Append      string `yaml:"append"`
	Base64      bool   `yaml:"base64"`
	ContentType string `yaml:"content_type"`
}

func Load(path string) (*MalleableProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}

	p := &MalleableProfile{}
	if err := yaml.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}

	setProfileDefaults(p)
	return p, nil
}

func setProfileDefaults(p *MalleableProfile) {
	if p.Sleep.Interval == 0 {
		p.Sleep.Interval = 60
	}
	if len(p.HTTP.Get.URI) == 0 {
		p.HTTP.Get.URI = []string{"/api/v1/status"}
	}
	if len(p.HTTP.Post.URI) == 0 {
		p.HTTP.Post.URI = []string{"/api/v1/data"}
	}
	if len(p.UserAgents) == 0 {
		p.UserAgents = []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
		}
	}
}

func (p *MalleableProfile) RandomURI(tx *HTTPTransaction) string {
	if len(tx.URI) == 0 {
		return "/"
	}
	return tx.URI[rand.Intn(len(tx.URI))]
}

func (p *MalleableProfile) RandomUserAgent() string {
	if len(p.UserAgents) == 0 {
		return "Mozilla/5.0"
	}
	return p.UserAgents[rand.Intn(len(p.UserAgents))]
}

// ApplyHeaders sets profile-defined headers on outgoing responses.
func (p *MalleableProfile) ApplyHeaders(headers map[string]string, tx *HTTPTransaction) map[string]string {
	result := make(map[string]string)
	for k, v := range tx.Headers {
		result[k] = v
	}
	for k, v := range headers {
		result[k] = v
	}
	return result
}

func (p *MalleableProfile) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Profile: %s\n", p.Name))
	b.WriteString(fmt.Sprintf("  Sleep: %ds (%d%% jitter)\n", p.Sleep.Interval, p.Sleep.Jitter))
	b.WriteString(fmt.Sprintf("  GET URIs: %v\n", p.HTTP.Get.URI))
	b.WriteString(fmt.Sprintf("  POST URIs: %v\n", p.HTTP.Post.URI))
	b.WriteString(fmt.Sprintf("  User-Agents: %d configured\n", len(p.UserAgents)))
	return b.String()
}
