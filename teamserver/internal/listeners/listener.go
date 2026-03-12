package listeners

import "context"

type Protocol string

const (
	ProtocolHTTP  Protocol = "http"
	ProtocolHTTPS Protocol = "https"
	ProtocolMTLS  Protocol = "mtls"
	ProtocolDNS   Protocol = "dns"
	ProtocolTCP   Protocol = "tcp"
	ProtocolSMB   Protocol = "smb"
)

type Config struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Protocol    Protocol          `json:"protocol"`
	BindAddress string            `json:"bind_address"`
	BindPort    int               `json:"bind_port"`
	Options     map[string]string `json:"options"`
}

type CheckIn struct {
	AgentID    string
	ExternalIP string
	Data       []byte
}

// Listener defines the interface every protocol listener must implement.
// Adding a new protocol (DNS, TCP, SMB) is just a matter of implementing this.
type Listener interface {
	ID() string
	Name() string
	Protocol() Protocol
	BindAddress() string
	BindPort() int
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	IsRunning() bool
	CheckIns() <-chan CheckIn
}
