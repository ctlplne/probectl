package agent

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration is a time.Duration that unmarshals from a YAML string like "30s".
type Duration time.Duration

// UnmarshalYAML parses a Go duration string.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Std returns the standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Config is the probectl-agent configuration (a YAML file plus PROBECTL_AGENT_* env
// overrides). It is the agent config-file schema contract.
type Config struct {
	ControlPlane ControlPlaneConfig `yaml:"control_plane"`
	TLS          TLSConfig          `yaml:"tls"`
	Identity     IdentityConfig     `yaml:"identity"`
	Agent        Meta               `yaml:"agent"`
	Buffer       BufferConfig       `yaml:"buffer"`
	Canaries     []CanaryConfig     `yaml:"canaries"`
	A2A          A2AConfig          `yaml:"a2a"`
}

// IdentityConfig wires automatic SVID rotation (Sprint 11): when Server is
// set, the runtime rotates the TLS material in place at ~2/3 of the leaf
// lifetime via POST /enroll/agent/rotate, proving the current identity. The
// files come from `probectl-agent enroll`; ClientMTLSConfigRotating hot-reads
// the swap, so rotation never restarts the agent.
type IdentityConfig struct {
	// Server is the control-plane HTTPS base URL (https://host:8443). Empty
	// disables automatic rotation (operator-managed certs keep working).
	Server string `yaml:"server"`
	// AutoRotate defaults true when Server is set; set false to only enroll.
	AutoRotate *bool `yaml:"auto_rotate"`
}

// A2AConfig controls participation in brokered agent-to-agent tests. When
// enabled, the agent polls the control plane for coordination tasks and can act
// as a responder or initiator.
type A2AConfig struct {
	Enabled bool `yaml:"enabled"`
	// AdvertiseHost is the address peers use to reach this agent's responder.
	// Empty auto-detects a non-loopback IP; set it explicitly behind NAT.
	AdvertiseHost string   `yaml:"advertise_host"`
	PollInterval  Duration `yaml:"poll_interval"`
	ResponderTTL  Duration `yaml:"responder_ttl"`
}

// ControlPlaneConfig is the control-plane connection.
type ControlPlaneConfig struct {
	GRPCAddr string `yaml:"grpc_addr"`
}

// TLSConfig is the agent's mTLS material. The agent's tenant + id are derived
// from CertFile's SPIFFE identity.
type TLSConfig struct {
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
	// CanaryCADir allowlists the ONE directory probe ca_file parameters may
	// reference (RED-008). Empty = the ca_file param is refused (default).
	CanaryCADir string `yaml:"canary_ca_dir"`
}

// Meta is agent-level metadata.
type Meta struct {
	Hostname          string   `yaml:"hostname"`
	Capabilities      []string `yaml:"capabilities"`
	HeartbeatInterval Duration `yaml:"heartbeat_interval"`
}

// BufferConfig is the store-and-forward buffer.
type BufferConfig struct {
	Dir        string `yaml:"dir"`
	MaxRecords int    `yaml:"max_records"`
}

// CanaryConfig configures one scheduled canary.
type CanaryConfig struct {
	Type     string            `yaml:"type"`
	Target   string            `yaml:"target"`
	Interval Duration          `yaml:"interval"`
	Timeout  Duration          `yaml:"timeout"`
	Params   map[string]string `yaml:"params"`
}

// Load reads, defaults, and validates the agent config from a YAML file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyEnv()
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyEnv() {
	override := func(env string, dst *string) {
		if v := os.Getenv(env); v != "" {
			*dst = v
		}
	}
	override("PROBECTL_AGENT_GRPC_ADDR", &c.ControlPlane.GRPCAddr)
	override("PROBECTL_AGENT_TLS_CERT_FILE", &c.TLS.CertFile)
	override("PROBECTL_AGENT_IDENTITY_SERVER", &c.Identity.Server)
	override("PROBECTL_AGENT_CANARY_CA_DIR", &c.TLS.CanaryCADir)
	override("PROBECTL_AGENT_TLS_KEY_FILE", &c.TLS.KeyFile)
	override("PROBECTL_AGENT_TLS_CA_FILE", &c.TLS.CAFile)
	override("PROBECTL_AGENT_BUFFER_DIR", &c.Buffer.Dir)
}

func (c *Config) applyDefaults() {
	if c.Agent.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			c.Agent.Hostname = h
		}
	}
	if c.Agent.HeartbeatInterval == 0 {
		c.Agent.HeartbeatInterval = Duration(30 * time.Second)
	}
	if c.Buffer.Dir == "" {
		c.Buffer.Dir = "/var/lib/probectl/agent/buffer"
	}
	if c.Buffer.MaxRecords == 0 {
		c.Buffer.MaxRecords = 10000
	}
	for i := range c.Canaries {
		if c.Canaries[i].Interval == 0 {
			c.Canaries[i].Interval = Duration(30 * time.Second)
		}
	}
	if c.A2A.PollInterval == 0 {
		c.A2A.PollInterval = Duration(2 * time.Second)
	}
	if c.A2A.ResponderTTL == 0 {
		c.A2A.ResponderTTL = Duration(15 * time.Second)
	}
}

func (c *Config) validate() error {
	if c.ControlPlane.GRPCAddr == "" {
		return fmt.Errorf("config: control_plane.grpc_addr is required")
	}
	if c.TLS.CertFile == "" || c.TLS.KeyFile == "" || c.TLS.CAFile == "" {
		return fmt.Errorf("config: tls.cert_file, tls.key_file, and tls.ca_file are required (mTLS)")
	}
	for i, cc := range c.Canaries {
		if cc.Type == "" {
			return fmt.Errorf("config: canaries[%d].type is required", i)
		}
	}
	return nil
}
