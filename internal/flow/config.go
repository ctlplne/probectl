package flow

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ListenerConfig is one protocol listener.
type ListenerConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

// BusConfig selects the bus backend for emission (memory | kafka).
type BusConfig struct {
	Mode    string   `yaml:"mode"`
	Brokers []string `yaml:"brokers"`
	// Namespace routes this tenant's batches onto its SILOED bus lane
	// (TENANT-107): topics become probectl.<namespace>.<...>. Empty = the
	// shared (pooled) lane. A malformed value refuses agent start (RED-006).
	Namespace string `yaml:"namespace"`
}

// Config is the flow-collector configuration: a YAML file with PROBECTL_FLOW_*
// environment overrides. Every key is documented in docs/configuration.md.
type Config struct {
	// TenantID binds every emitted record to one tenant (F50) — required. In
	// production the agent derives identity from its SPIFFE client cert (like
	// the canary agent); the explicit field supports the lightweight deploy.
	TenantID string `yaml:"tenant_id"`
	AgentID  string `yaml:"agent_id"`

	Bus BusConfig `yaml:"bus"`

	// NetFlow serves v5 AND v9 (version-sniffed) on one socket; IPFIX and
	// sFlow have their own IANA ports. Disable any listener you don't run.
	NetFlow ListenerConfig `yaml:"netflow"`
	IPFIX   ListenerConfig `yaml:"ipfix"`
	SFlow   ListenerConfig `yaml:"sflow"`

	// Batching: a flush goes out when BatchSize records accumulate or
	// FlushInterval elapses, whichever is first.
	BatchSize     int           `yaml:"batch_size"`
	FlushInterval time.Duration `yaml:"flush_interval"`

	// Template state bounds (v9/IPFIX; untrusted input — CLAUDE.md §7).
	TemplateTTL  time.Duration `yaml:"template_ttl"`
	MaxTemplates int           `yaml:"max_templates"`

	// High-volume ingest tuning.
	ReadBufferBytes int `yaml:"read_buffer_bytes"` // kernel socket buffer
	QueueSize       int `yaml:"queue_size"`        // decode -> flush channel
	Workers         int `yaml:"workers"`           // readers per socket
}

// Default returns the built-in defaults: all three listeners on their IANA
// ports, memory bus, 1k/2s batching, 30m template TTL, 4 MiB socket buffers.
func Default() *Config {
	host, _ := os.Hostname()
	return &Config{
		AgentID:         host,
		Bus:             BusConfig{Mode: "memory"},
		NetFlow:         ListenerConfig{Enabled: true, Listen: ":2055"},
		IPFIX:           ListenerConfig{Enabled: true, Listen: ":4739"},
		SFlow:           ListenerConfig{Enabled: true, Listen: ":6343"},
		BatchSize:       1000,
		FlushInterval:   2 * time.Second,
		TemplateTTL:     30 * time.Minute,
		MaxTemplates:    4096,
		ReadBufferBytes: 4 << 20,
		QueueSize:       65536,
		Workers:         2,
	}
}

// Load reads the YAML config at path (if non-empty) over the defaults, then
// applies PROBECTL_FLOW_* environment overrides, then validates.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("flow: read config: %w", err)
		}
		if err := yaml.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("flow: parse config: %w", err)
		}
	}
	cfg.applyEnv(os.Getenv)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnv layers PROBECTL_FLOW_* overrides (exported for table-driven tests
// via the getenv seam).
func (c *Config) applyEnv(getenv func(string) string) {
	set := func(key string, dst *string) {
		if v := getenv(key); v != "" {
			*dst = v
		}
	}
	setBool := func(key string, dst *bool) {
		if v := getenv(key); v != "" {
			if b, err := strconv.ParseBool(v); err == nil {
				*dst = b
			}
		}
	}
	setInt := func(key string, dst *int) {
		if v := getenv(key); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				*dst = n
			}
		}
	}
	setDur := func(key string, dst *time.Duration) {
		if v := getenv(key); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				*dst = d
			}
		}
	}

	set("PROBECTL_FLOW_TENANT", &c.TenantID)
	set("PROBECTL_FLOW_BUS_NAMESPACE", &c.Bus.Namespace)
	set("PROBECTL_FLOW_AGENT_ID", &c.AgentID)
	set("PROBECTL_FLOW_BUS_MODE", &c.Bus.Mode)
	if v := getenv("PROBECTL_FLOW_BUS_BROKERS"); v != "" {
		c.Bus.Brokers = splitCSV(v)
	}
	setBool("PROBECTL_FLOW_NETFLOW_ENABLED", &c.NetFlow.Enabled)
	set("PROBECTL_FLOW_NETFLOW_LISTEN", &c.NetFlow.Listen)
	setBool("PROBECTL_FLOW_IPFIX_ENABLED", &c.IPFIX.Enabled)
	set("PROBECTL_FLOW_IPFIX_LISTEN", &c.IPFIX.Listen)
	setBool("PROBECTL_FLOW_SFLOW_ENABLED", &c.SFlow.Enabled)
	set("PROBECTL_FLOW_SFLOW_LISTEN", &c.SFlow.Listen)
	setInt("PROBECTL_FLOW_BATCH_SIZE", &c.BatchSize)
	setDur("PROBECTL_FLOW_FLUSH_INTERVAL", &c.FlushInterval)
	setDur("PROBECTL_FLOW_TEMPLATE_TTL", &c.TemplateTTL)
	setInt("PROBECTL_FLOW_MAX_TEMPLATES", &c.MaxTemplates)
	setInt("PROBECTL_FLOW_READ_BUFFER_BYTES", &c.ReadBufferBytes)
	setInt("PROBECTL_FLOW_QUEUE_SIZE", &c.QueueSize)
	setInt("PROBECTL_FLOW_WORKERS", &c.Workers)
}

// Validate enforces the invariants New depends on.
func (c *Config) Validate() error {
	if c.TenantID == "" {
		return errors.New("flow: tenant_id is required (PROBECTL_FLOW_TENANT)")
	}
	if !c.NetFlow.Enabled && !c.IPFIX.Enabled && !c.SFlow.Enabled {
		return errors.New("flow: no listener enabled")
	}
	if c.BatchSize <= 0 || c.QueueSize <= 0 || c.FlushInterval <= 0 {
		return errors.New("flow: batch_size, queue_size and flush_interval must be positive")
	}
	return nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
