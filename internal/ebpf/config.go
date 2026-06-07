package ebpf

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the eBPF agent configuration: a YAML file with PROBECTL_EBPF_*
// environment overrides. Every key is documented in docs/configuration.md.
type Config struct {
	// TenantID binds every emitted flow to one tenant (F50). In production the
	// agent derives this from its SPIFFE client-cert identity (like the canary
	// agent); the explicit field supports the lightweight / single-tenant deploy.
	TenantID string `yaml:"tenant_id"`
	Host     string `yaml:"host"`

	// Bus is where flow + service-edge batches are published (probectl.ebpf.flows).
	Bus BusConfig `yaml:"bus"`

	// FixturePath, when set, replays recorded flows instead of loading eBPF —
	// the no-kernel path used by CI, macOS, and unprivileged containers.
	FixturePath string `yaml:"fixture_path"`

	// L7FixturePath, when set, replays recorded L7 events (the no-kernel path for
	// L7 visibility, S21). Live L7 capture otherwise requires -tags ebpf.
	L7FixturePath string `yaml:"l7_fixture_path"`

	// ProcRoot is the procfs root used for enrichment ("" => /proc).
	ProcRoot string `yaml:"proc_root"`

	// FlushInterval is how often accumulated flows + the service map are emitted.
	FlushInterval time.Duration `yaml:"flush_interval"`

	// RingBufferBytes sizes the kernel ring buffer (live source only); it is
	// rounded to a valid power-of-two page multiple at load (U-050).
	RingBufferBytes int `yaml:"ring_buffer_bytes"`

	// TLS-plaintext capture policy (U-003): live sslsniff capture is OFF by
	// default and requires BOTH the enable flag and an explicit per-tenant
	// consent naming this agent's tenant. L7CaptureRedaction selects the
	// boundary policy ("headers" default — bodies zeroed before any
	// retention; "full" only for consented debugging).
	L7CaptureEnabled       bool   `yaml:"l7_capture_enabled"`
	L7CaptureConsentTenant string `yaml:"l7_capture_consent_tenant"`
	L7CaptureRedaction     string `yaml:"l7_capture_redaction"`
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
		Host:               host,
		Bus:                BusConfig{Mode: "memory"},
		ProcRoot:           "/proc",
		FlushInterval:      10 * time.Second,
		RingBufferBytes:    1 << 24,
		L7CaptureRedaction: RedactHeaders, // U-003: capture off by default; bodies zeroed when on
	}
}

// Load reads the YAML config at path (if non-empty), applies PROBECTL_EBPF_*
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
	if v := getenv("PROBECTL_EBPF_TENANT_ID"); v != "" {
		c.TenantID = v
	}
	if v := getenv("PROBECTL_EBPF_HOST"); v != "" {
		c.Host = v
	}
	if v := getenv("PROBECTL_EBPF_BUS_MODE"); v != "" {
		c.Bus.Mode = v
	}
	if v := getenv("PROBECTL_EBPF_BUS_BROKERS"); v != "" {
		c.Bus.Brokers = splitComma(v)
	}
	if v := getenv("PROBECTL_EBPF_FIXTURE_PATH"); v != "" {
		c.FixturePath = v
	}
	if v := getenv("PROBECTL_EBPF_L7_FIXTURE_PATH"); v != "" {
		c.L7FixturePath = v
	}
	if v := getenv("PROBECTL_EBPF_PROC_ROOT"); v != "" {
		c.ProcRoot = v
	}
	if v := getenv("PROBECTL_EBPF_RING_BUFFER_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.RingBufferBytes = n
		}
	}
	if v := getenv("PROBECTL_EBPF_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.FlushInterval = d
		}
	}
	if v := getenv("PROBECTL_EBPF_L7_CAPTURE"); v != "" {
		c.L7CaptureEnabled = v == "true"
	}
	if v := getenv("PROBECTL_EBPF_L7_CONSENT_TENANT"); v != "" {
		c.L7CaptureConsentTenant = v
	}
	if v := getenv("PROBECTL_EBPF_L7_REDACTION"); v != "" {
		c.L7CaptureRedaction = v
	}
}

func (c *Config) validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("ebpf: tenant_id is required (PROBECTL_EBPF_TENANT_ID or config)")
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
	if c.L7CaptureRedaction != "" && !validRedactionMode(c.L7CaptureRedaction) {
		return fmt.Errorf("ebpf: l7_capture_redaction %q (want %s|%s)", c.L7CaptureRedaction, RedactHeaders, RedactFull)
	}
	if c.L7CaptureEnabled && c.L7CaptureConsentTenant == "" {
		return fmt.Errorf("ebpf: l7_capture_enabled requires l7_capture_consent_tenant (the EXPLICIT per-tenant consent, U-003)")
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
