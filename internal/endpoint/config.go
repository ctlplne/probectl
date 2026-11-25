// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/configschema"
)

const (
	ConfigAPIVersion   = "probectl.io/endpoint/v1"
	maxConfigFileBytes = 1 << 20
)

// Config is the endpoint agent configuration: a YAML file with PROBECTL_ENDPOINT_*
// environment overrides. Every key is documented in docs/configuration.md.
type Config struct {
	APIVersion    string `yaml:"apiVersion"`
	SchemaVersion int    `yaml:"schema_version,omitempty"`

	// TenantID binds every emitted DEM result to one tenant (F50).
	//
	// In enrolled mode this is checked against the device certificate. In
	// direct-bus mode the receiver verifies the assertion against the registry.
	TenantID string `yaml:"tenant_id"`
	// AgentID identifies this device in the fleet ("" => the hostname).
	AgentID string `yaml:"agent_id"`

	// Bus is where DEM results are published (probectl.endpoint.results).
	Bus BusConfig `yaml:"bus"`
	// Control selects the certificate-bound agent transport for managed endpoints.
	Control ControlConfig `yaml:"control"`

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

type ControlConfig struct {
	Address       string `yaml:"address"`        // operator's mTLS agent listener, host:port
	EnrollmentURL string `yaml:"enrollment_url"` // operator's HTTPS control plane, for SVID rotation
	IdentityDir   string `yaml:"identity_dir"`   // private device enrollment directory
}

// BusConfig selects the bus backend for emission.
type BusConfig struct {
	Mode    string   `yaml:"mode"`    // memory | nats | kafka
	Brokers []string `yaml:"brokers"` // required for networked modes
	// Namespace routes this tenant's results onto its SILOED bus lane
	// (TENANT-107). Empty = shared lane; malformed refuses start (RED-006).
	Namespace string `yaml:"namespace"`
}

// Default returns the built-in defaults: memory bus, a 60s interval, balanced
// privacy, default thresholds, and — deliberately — NO probe targets.
//
// Shipping external anycast hosts (Cloudflare/Google) as defaults would make a
// freshly installed agent beacon out every interval with no operator intent,
// a default outbound phone-home that contradicts the sovereign/air-gap
// positioning (docs/guardrails.md G7-2). Targets are operator-chosen input
// instead: until one is configured the agent probes nothing off-device (it
// still measures local Wi-Fi/gateway health). See docs/endpoint-dem.md.
func Default() *Config {
	host, _ := os.Hostname()
	return &Config{
		AgentID:        host,
		Bus:            BusConfig{Mode: "memory"},
		Interval:       60 * time.Second,
		Targets:        nil,
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
		data, err := readConfigFile(path)
		if err != nil {
			return nil, fmt.Errorf("read endpoint config: %w", err)
		}
		if err := decodeConfigYAML(data, cfg); err != nil {
			return nil, fmt.Errorf("parse endpoint config: %w", err)
		}
	}
	cfg.applyEnv(os.Getenv)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func readConfigFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, maxConfigFileBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(raw) > maxConfigFileBytes {
		return nil, fmt.Errorf("config file exceeds %d-byte limit", maxConfigFileBytes)
	}
	return raw, nil
}

func decodeConfigYAML(raw []byte, cfg *Config) error {
	if err := configschema.DecodeStrictYAML(raw, cfg); err != nil {
		return err
	}
	apiVersion, err := configschema.ResolveAPIVersion("endpoint", cfg.APIVersion, cfg.SchemaVersion, ConfigAPIVersion)
	if err != nil {
		return err
	}
	cfg.APIVersion = apiVersion
	return nil
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
	if v := getenv("PROBECTL_ENDPOINT_CONTROL_ADDR"); v != "" {
		c.Control.Address = v
	}
	if v := getenv("PROBECTL_ENDPOINT_ENROLLMENT_URL"); v != "" {
		c.Control.EnrollmentURL = v
	}
	if v := getenv("PROBECTL_ENDPOINT_IDENTITY_DIR"); v != "" {
		c.Control.IdentityDir = v
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
	if c.Control != (ControlConfig{}) {
		host, port, err := net.SplitHostPort(c.Control.Address)
		portNumber, portErr := strconv.ParseUint(port, 10, 16)
		if err != nil || host == "" || portErr != nil || portNumber == 0 || strings.ContainsAny(host, "/\\@?# \t\r\n") {
			return fmt.Errorf("endpoint: control.address must be a host and port")
		}
		server, err := url.Parse(c.Control.EnrollmentURL)
		if err != nil || server.Scheme != "https" || server.Hostname() == "" || server.User != nil ||
			(server.Path != "" && server.Path != "/") || server.RawQuery != "" || server.ForceQuery || server.Fragment != "" {
			return fmt.Errorf("endpoint: control.enrollment_url must be an HTTPS origin")
		}
		if strings.TrimSpace(c.Control.IdentityDir) == "" || c.Bus.Mode != "memory" || len(c.Bus.Brokers) != 0 || c.Bus.Namespace != "" {
			return fmt.Errorf("endpoint: control transport requires identity_dir and no direct bus configuration")
		}
	}
	switch c.Bus.Mode {
	case "memory", "nats", "kafka":
	default:
		return fmt.Errorf("endpoint: invalid bus mode %q (memory|nats|kafka)", c.Bus.Mode)
	}
	if c.Bus.Mode != "memory" && len(c.Bus.Brokers) == 0 {
		return fmt.Errorf("endpoint: %s bus requires brokers", c.Bus.Mode)
	}
	if c.Interval <= 0 {
		return fmt.Errorf("endpoint: interval must be > 0")
	}
	// No target is required: the agent ships none by default (no-phone-home,
	// docs/guardrails.md G7-2) and simply probes nothing off-device until an
	// operator configures targets. The collector handles an empty list
	// gracefully — the last-mile trace and session probes are skipped.
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
