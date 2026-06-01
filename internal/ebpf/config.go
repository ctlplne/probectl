package ebpf

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the eBPF agent configuration: a YAML file with NETCTL_EBPF_*
// environment overrides. Every key is documented in docs/configuration.md.
type Config struct {
	// TenantID binds every emitted flow to one tenant (F50). In production the
	// agent derives this from its SPIFFE client-cert identity (like the canary
	// agent); the explicit field supports the lightweight / single-tenant deploy.
	TenantID string `yaml:"tenant_id"`
	Host     string `yaml:"host"`

	// Bus is where flow + service-edge batches are published (netctl.ebpf.flows).
	Bus BusConfig `yaml:"bus"`

	// FixturePath, when set, replays recorded flows instead of loading eBPF —
	// the no-kernel path used by CI, macOS, and unprivileged containers.
	FixturePath string `yaml:"fixture_path"`

	// ProcRoot is the procfs root used for enrichment ("" => /proc).
	ProcRoot string `yaml:"proc_root"`

	// FlushInterval is how often accumulated flows + the service map are emitted.
	FlushInterval time.Duration `yaml:"flush_interval"`

	// RingBufferBytes sizes the kernel ring buffer (live source only).
	RingBufferBytes int `yaml:"ring_buffer_bytes"`
}

// BusConfig selects the bus backend for emission.
type BusConfig struct {
	Mode    string   `yaml:"mode"`    // memory | kafka
	Brokers []string `yaml:"brokers"` // kafka mode
}

// Default returns the built-in defaults (memory bus, /proc, 10s flush, 16 MiB ring).
func Default() *Config {
	host, _ := os.Hostname()
	return &Config{
		Host:            host,
		Bus:             BusConfig{Mode: "memory"},
		ProcRoot:        "/proc",
		FlushInterval:   10 * time.Second,
		RingBufferBytes: 1 << 24,
	}
}

// Load reads the YAML config at path (if non-empty), applies NETCTL_EBPF_*
// environment overrides, and validates the result.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ebpf config: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse ebpf config: %w", err)
		}
	}
	cfg.applyEnv(os.Getenv)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyEnv(getenv func(string) string) {
	if v := getenv("NETCTL_EBPF_TENANT_ID"); v != "" {
		c.TenantID = v
	}
	if v := getenv("NETCTL_EBPF_HOST"); v != "" {
		c.Host = v
	}
	if v := getenv("NETCTL_EBPF_BUS_MODE"); v != "" {
		c.Bus.Mode = v
	}
	if v := getenv("NETCTL_EBPF_BUS_BROKERS"); v != "" {
		c.Bus.Brokers = splitComma(v)
	}
	if v := getenv("NETCTL_EBPF_FIXTURE_PATH"); v != "" {
		c.FixturePath = v
	}
	if v := getenv("NETCTL_EBPF_PROC_ROOT"); v != "" {
		c.ProcRoot = v
	}
	if v := getenv("NETCTL_EBPF_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.FlushInterval = d
		}
	}
}

func (c *Config) validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("ebpf: tenant_id is required (NETCTL_EBPF_TENANT_ID or config)")
	}
	switch c.Bus.Mode {
	case "memory", "kafka":
	default:
		return fmt.Errorf("ebpf: invalid bus mode %q (memory|kafka)", c.Bus.Mode)
	}
	if c.Bus.Mode == "kafka" && len(c.Bus.Brokers) == 0 {
		return fmt.Errorf("ebpf: kafka bus requires brokers")
	}
	if c.FlushInterval <= 0 {
		return fmt.Errorf("ebpf: flush_interval must be > 0")
	}
	return nil
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
