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

// Config is the netctl-agent configuration (a YAML file plus NETCTL_AGENT_* env
// overrides). It is the agent config-file schema contract.
type Config struct {
	ControlPlane ControlPlaneConfig `yaml:"control_plane"`
	TLS          TLSConfig          `yaml:"tls"`
	Agent        Meta               `yaml:"agent"`
	Buffer       BufferConfig       `yaml:"buffer"`
	Canaries     []CanaryConfig     `yaml:"canaries"`
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
	override("NETCTL_AGENT_GRPC_ADDR", &c.ControlPlane.GRPCAddr)
	override("NETCTL_AGENT_TLS_CERT_FILE", &c.TLS.CertFile)
	override("NETCTL_AGENT_TLS_KEY_FILE", &c.TLS.KeyFile)
	override("NETCTL_AGENT_TLS_CA_FILE", &c.TLS.CAFile)
	override("NETCTL_AGENT_BUFFER_DIR", &c.Buffer.Dir)
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
		c.Buffer.Dir = "/var/lib/netctl/agent/buffer"
	}
	if c.Buffer.MaxRecords == 0 {
		c.Buffer.MaxRecords = 10000
	}
	for i := range c.Canaries {
		if c.Canaries[i].Interval == 0 {
			c.Canaries[i].Interval = Duration(30 * time.Second)
		}
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
