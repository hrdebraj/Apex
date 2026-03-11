package listeners

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// DNSListener receives agent data encoded in DNS queries (TXT, A, AAAA records).
// Agents encode check-in data as subdomain labels; responses carry tasking in TXT records.
type DNSListener struct {
	config   Config
	server   *dns.Server
	checkins chan CheckIn
	running  bool
	mu       sync.RWMutex
}

func NewDNS(cfg Config) *DNSListener {
	return &DNSListener{
		config:   cfg,
		checkins: make(chan CheckIn, 256),
	}
}

func (d *DNSListener) ID() string              { return d.config.ID }
func (d *DNSListener) Name() string             { return d.config.Name }
func (d *DNSListener) Protocol() Protocol       { return ProtocolDNS }
func (d *DNSListener) BindAddress() string      { return d.config.BindAddress }
func (d *DNSListener) BindPort() int            { return d.config.BindPort }
func (d *DNSListener) CheckIns() <-chan CheckIn { return d.checkins }

func (d *DNSListener) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}

func (d *DNSListener) Start(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", d.config.BindAddress, d.config.BindPort)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", d.handleQuery)

	d.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: mux,
	}

	d.mu.Lock()
	d.running = true
	d.mu.Unlock()

	log.Info().
		Str("protocol", "dns").
		Str("addr", addr).
		Str("name", d.config.Name).
		Msg("DNS listener started")

	go func() {
		<-ctx.Done()
		d.Stop(context.Background())
	}()

	err := d.server.ListenAndServe()
	if err != nil {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
		return fmt.Errorf("dns serve: %w", err)
	}
	return nil
}

func (d *DNSListener) Stop(_ context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.server != nil {
		d.server.Shutdown()
	}
	d.running = false

	log.Info().Str("name", d.config.Name).Msg("DNS listener stopped")
	return nil
}

func (d *DNSListener) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		domain := strings.TrimSuffix(q.Name, ".")
		parts := strings.SplitN(domain, ".", 2)

		// Extract agent data from subdomain label (base64-encoded)
		if len(parts) >= 1 {
			decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err == nil && len(decoded) > 0 {
				remoteAddr := w.RemoteAddr().String()
				ip, _, _ := net.SplitHostPort(remoteAddr)

				d.checkins <- CheckIn{
					AgentID:    extractAgentIDFromDNS(decoded),
					ExternalIP: ip,
					Data:       decoded,
				}
			}
		}

		switch q.Qtype {
		case dns.TypeTXT:
			// TXT records carry tasking data back to the agent
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{""},
			})
		case dns.TypeA:
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("127.0.0.1"),
			})
		case dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
				AAAA: net.ParseIP("::1"),
			})
		}
	}

	w.WriteMsg(m)
}

func extractAgentIDFromDNS(data []byte) string {
	// First 8 bytes of the decoded payload are the agent ID prefix.
	// Full protocol will be defined when the agent is built.
	if len(data) >= 8 {
		return fmt.Sprintf("%x", data[:8])
	}
	return fmt.Sprintf("%x", data)
}
