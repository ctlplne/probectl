package endpoint

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the endpoint agent configuration: a YAML file with PROBECTL_ENDPOINT_*
// environment overrides. Every key is documented in docs/configuration.md.
type Config struct {
	// TenantID binds every emitted DEM result to one tenant (F50). In production
	// the agent derives this from its SPIFFE client-cert identity (like the canary
	// agent); the explicit field supports the lightweight / single-tenant deploy.
	TenantID string `yaml:"tenant_id"`
	// AgentID identifies this device in the fleet ("" => the hostname).
	AgentID string `yaml:"agent_id"`

	// Bus is where DEM results are published (probectl.endpoint.results).
	Bus BusConfig `yaml:"bus"`

	// Interval is how often a sample is collected.
	Interval time.Duration `yaml:"interval"`
	// Targets are the key destinations for the last-mile trace (first target) and
	// browser-session timings (all targets).
	Targets []string `yaml:"targets"`
	// MaxHops caps the last-mile trace length; Probes is samples per hop.
	MaxHops int `yaml:"max_hops"`
	Probes  int `yaml:"probes"`
	// SessionTimeout bounds each browser-session probe.
	SessionTimeout time.Duration `yaml:"session_timeout"`

	// Privacy controls which identifiers are retained (minimization).
	Privacy Privacy `yaml:"privacy"`
	// Thresholds tune the slowdown-attribution engine.
	Thresholds Thresholds `yaml:"thresholds"`
}

// BusConfig selects the bus backend for emission.
type BusConfig struct {
	Mode    string   `yaml:"mode"`    // memory | kafka
	Brokers []string `yaml:"brokers"` // kafka mode
	// Namespace routes this tenant's results onto its SILOED bus lane
	// (TENANT-107). Empty = shared lane; malformed refuses start (RED-006).
	Namespace string `yaml:"namespace"`
}

// Default returns the built-in defaults: memory bus, a 60s interval, balanced
// privacy, default thresholds, and Cloudflare/Google anycast as neutral targets.
func Default() *Config {
	host, _ := os.Hostname()
	return &Config{
		AgentID:        host,
		Bus:            BusConfig{Mode: "memory"},
		Interval:       60 * time.Second,
		Targets:        []string{"https://1.1.1.1", "https://www.google.com"},
		MaxHops:        20,
		Probes:         3,
		SessionTimeout: 15 * time.Second,
		Privacy:        DefaultPrivacy(),
		Thresholds:     DefaultThresholds(),
	}
}

// Load reads the YAML config at path (if non-empty), applies PROBECTL_ENDPOINT_*
// environment overrides, and validates the result.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read endpoint config: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse endpoint config: %w", err)
		}
	}
	cfg.applyEnv(os.Getenv)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) applyEnv(getenv func(string) string) {
	if v := getenv("PROBECTL_ENDPOINT_TENANT_ID"); v != "" {
		c.TenantID = v
	}
	if v := getenv("PROBECTL_ENDPOINT_AGENT_ID"); v != "" {
		c.AgentID = v
	}
	if v := getenv("PROBECTL_ENDPOINT_BUS_MODE"); v != "" {
		c.Bus.Mode = v
	}
	if v := getenv("PROBECTL_ENDPOINT_BUS_BROKERS"); v != "" {
		c.Bus.Brokers = splitComma(v)
	}
	if v := getenv("PROBECTL_ENDPOINT_BUS_NAMESPACE"); v != "" {
		c.Bus.Namespace = v
	}
	if v := getenv("PROBECTL_ENDPOINT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Interval = d
		}
	}
	if v := getenv("PROBECTL_ENDPOINT_TARGETS"); v != "" {
		c.Targets = splitComma(v)
	}
	if v := getenv("PROBECTL_ENDPOINT_MAX_HOPS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxHops = n
		}
	}
	// Privacy toggles: PROBECTL_ENDPOINT_COLLECT_{SSID,BSSID,GATEWAY_IP,PUBLIC_HOPS}.
	c.Privacy.CollectSSID = envBool(getenv, "PROBECTL_ENDPOINT_COLLECT_SSID", c.Privacy.CollectSSID)
	c.Privacy.CollectBSSID = envBool(getenv, "PROBECTL_ENDPOINT_COLLECT_BSSID", c.Privacy.CollectBSSID)
	c.Privacy.CollectGatewayIP = envBool(getenv, "PROBECTL_ENDPOINT_COLLECT_GATEWAY_IP", c.Privacy.CollectGatewayIP)
	c.Privacy.CollectPublicHops = envBool(getenv, "PROBECTL_ENDPOINT_COLLECT_PUBLIC_HOPS", c.Privacy.CollectPublicHops)
}

func (c *Config) validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("endpoint: tenant_id is required (PROBECTL_ENDPOINT_TENANT_ID or config)")
	}
	switch c.Bus.Mode {
	case "memory", "kafka":
	default:
		return fmt.Errorf("endpoint: invalid bus mode %q (memory|kafka)", c.Bus.Mode)
	}
	if c.Bus.Mode == "kafka" && len(c.Bus.Brokers) == 0 {
		return fmt.Errorf("endpoint: kafka bus requires brokers")
	}
	if c.Interval <= 0 {
		return fmt.Errorf("endpoint: interval must be > 0")
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("endpoint: at least one target is required")
	}
	if c.MaxHops <= 0 {
		c.MaxHops = 20
	}
	if c.Probes <= 0 {
		c.Probes = 3
	}
	return nil
}

func envBool(getenv func(string) string, key string, def bool) bool {
	v := getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return b
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
