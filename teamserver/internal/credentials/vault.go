package credentials

import (
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

type Credential struct {
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id,omitempty"`
	Domain    string    `json:"domain,omitempty"`
	Username  string    `json:"username"`
	Secret    string    `json:"secret"`
	Type      string    `json:"type"` // plaintext, ntlm, kerberos, certificate, token
	Source    string    `json:"source,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Vault struct {
	db *pgxpool.Pool
}

func NewVault(db *pgxpool.Pool) *Vault {
	return &Vault{db: db}
}

func (v *Vault) Add(ctx context.Context, c *Credential) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}

	exists, _ := v.exists(ctx, c.Domain, c.Username, c.Secret)
	if exists {
		return nil
	}

	_, err := v.db.Exec(ctx,
		`INSERT INTO credentials (id, agent_id, domain, username, secret, type, source, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		c.ID, nilIfEmpty(c.AgentID), c.Domain, c.Username, c.Secret, c.Type, c.Source, c.CreatedAt)
	if err != nil {
		log.Warn().Err(err).Str("username", c.Username).Msg("Failed to store credential")
		return err
	}

	log.Info().
		Str("username", c.Username).
		Str("type", c.Type).
		Str("source", c.Source).
		Msg("Credential captured")
	return nil
}

func (v *Vault) List(ctx context.Context) ([]Credential, error) {
	rows, err := v.db.Query(ctx,
		`SELECT id, COALESCE(agent_id::text, ''), COALESCE(domain, ''), username, secret, type, COALESCE(source, ''), created_at
		 FROM credentials ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.AgentID, &c.Domain, &c.Username, &c.Secret, &c.Type, &c.Source, &c.CreatedAt); err != nil {
			continue
		}
		creds = append(creds, c)
	}
	if creds == nil {
		creds = []Credential{}
	}
	return creds, nil
}

func (v *Vault) Delete(ctx context.Context, id string) error {
	_, err := v.db.Exec(ctx, `DELETE FROM credentials WHERE id = $1`, id)
	return err
}

func (v *Vault) exists(ctx context.Context, domain, username, secret string) (bool, error) {
	var count int
	err := v.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM credentials WHERE domain = $1 AND username = $2 AND secret = $3`,
		domain, username, secret).Scan(&count)
	return count > 0, err
}

func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

var (
	samHashRe   = regexp.MustCompile(`(?m)^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::?\s*$`)
	ntlmHashRe  = regexp.MustCompile(`(?m)^(?:([^\\]+)\\)?([^:]+):([a-fA-F0-9]{32})(?::([a-fA-F0-9]{32}))?\s*$`)
	credPairRe  = regexp.MustCompile(`(?m)(?:Username|User|LOGIN)[\s:=]+([^\s]+)\s+(?:Password|Pass|PASS)[\s:=]+([^\s]+)`)
)

// ParseOutput scans task output for credential patterns and stores any matches.
func (v *Vault) ParseOutput(ctx context.Context, agentID, source, output string) {
	// SAM hash format: user:rid:lm_hash:ntlm_hash:::
	for _, m := range samHashRe.FindAllStringSubmatch(output, -1) {
		v.Add(ctx, &Credential{
			AgentID:  agentID,
			Username: m[1],
			Secret:   m[3] + ":" + m[4],
			Type:     "ntlm",
			Source:   source,
		})
	}

	// DOMAIN\user:ntlm_hash or DOMAIN\user:lm:ntlm
	for _, m := range ntlmHashRe.FindAllStringSubmatch(output, -1) {
		secret := m[3]
		if m[4] != "" {
			secret = m[3] + ":" + m[4]
		}
		v.Add(ctx, &Credential{
			AgentID:  agentID,
			Domain:   m[1],
			Username: m[2],
			Secret:   secret,
			Type:     "ntlm",
			Source:   source,
		})
	}

	// Username: X Password: Y pairs
	for _, m := range credPairRe.FindAllStringSubmatch(output, -1) {
		domain := ""
		user := m[1]
		if parts := strings.SplitN(user, "\\", 2); len(parts) == 2 {
			domain = parts[0]
			user = parts[1]
		}
		v.Add(ctx, &Credential{
			AgentID:  agentID,
			Domain:   domain,
			Username: user,
			Secret:   m[2],
			Type:     "plaintext",
			Source:   source,
		})
	}
}
