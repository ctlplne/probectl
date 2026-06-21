// SPDX-License-Identifier: LicenseRef-probectl-TBD

package device

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/configschema"
)

const ConfigAPIVersion = "probectl.io/device-agent/v1"

// Device transports.
const (
	TransportSNMPv2c = "snmpv2c"
	TransportSNMPv3  = "snmpv3"
	TransportGNMI    = "gnmi"
)

// GNMIConfig is the per-device gNMI subscription configuration.
type GNMIConfig struct {
	// Paths are OpenConfig subscription paths. Empty selects the defaults:
	// /interfaces/interface/state/counters and .../state/oper-status.
	Paths []string `yaml:"paths"`
	// SampleInterval for SAMPLE-mode subscriptions (default 30s).
	SampleInterval time.Duration `yaml:"sample_interval"`
	// CAFile verifies the device certificate against a private CA. System
	// roots are used when empty. Verification is never disabled (CLAUDE.md §7
	// guardrail 12).
	CAFile string `yaml:"ca_file"`
	// Plaintext dials without TLS — an explicit lab-only opt-in, loudly logged.
	Plaintext bool `yaml:"plaintext"`
}

// Target is one polled/subscribed device (the per-device config entry).
type Target struct {
	Address   string `yaml:"address"`
	Port      uint16 `yaml:"port"`      // default: 161 (snmp) / 9339 (gnmi)
	Transport string `yaml:"transport"` // snmpv2c | snmpv3 | gnmi
	// Credential NAMES the secret resolved via the CredentialSource seam —
	// never the secret itself (guardrail 6; S41 plugs Vault into the seam).
	Credential string        `yaml:"credential"`
	Interval   time.Duration `yaml:"interval"` // SNMP poll cadence (default 60s)
	Sensors    bool          `yaml:"sensors"`  // entity temperature sensors (SNMP)
	GNMI       GNMIConfig    `yaml:"gnmi"`
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

// Config is the device-telemetry collector configuration: a YAML file with
// PROBECTL_DEVICE_* environment overrides. Every key is documented in
// docs/configuration.md.
type Config struct {
	APIVersion    string `yaml:"apiVersion"`
	SchemaVersion int    `yaml:"schema_version,omitempty"`

	// TenantID binds every emitted metric to one tenant (F50) — required.
	TenantID string `yaml:"tenant_id"`
	AgentID  string `yaml:"agent_id"`

	Bus BusConfig `yaml:"bus"`

	Devices []Target `yaml:"devices"`
}

// Default returns the built-in defaults (memory bus, hostname agent id).
func Default() *Config {
	host, _ := os.Hostname()
	return &Config{AgentID: host, Bus: BusConfig{Mode: "memory"}}
}

// Load reads the YAML config at path (if non-empty) over the defaults, then
// applies PROBECTL_DEVICE_* environment overrides, then validates. Devices
// themselves are file-config (structured); env can supply the tenant, agent,
// bus, and a single quick-start device (PROBECTL_DEVICE_TARGET).
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("device: read config: %w", err)
		}
		if err := decodeConfigYAML(raw, cfg); err != nil {
			return nil, fmt.Errorf("device: parse config: %w", err)
		}
	}
	cfg.applyEnv(os.Getenv)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func decodeConfigYAML(raw []byte, cfg *Config) error {
	if err := configschema.DecodeStrictYAML(raw, cfg); err != nil {
		return err
	}
	apiVersion, err := configschema.ResolveAPIVersion("device", cfg.APIVersion, cfg.SchemaVersion, ConfigAPIVersion)
	if err != nil {
		return err
	}
	cfg.APIVersion = apiVersion
	return nil
}

// applyEnv layers PROBECTL_DEVICE_* overrides (getenv seam for tests).
func (c *Config) applyEnv(getenv func(string) string) {
	if v := getenv("PROBECTL_DEVICE_TENANT"); v != "" {
		c.TenantID = v
	}
	if v := getenv("PROBECTL_DEVICE_AGENT_ID"); v != "" {
		c.AgentID = v
	}
	if v := getenv("PROBECTL_DEVICE_BUS_MODE"); v != "" {
		c.Bus.Mode = v
	}
	if v := getenv("PROBECTL_DEVICE_BUS_NAMESPACE"); v != "" {
		c.Bus.Namespace = v
	}
	if v := getenv("PROBECTL_DEVICE_BUS_BROKERS"); v != "" {
		parts := strings.Split(v, ",")
		c.Bus.Brokers = c.Bus.Brokers[:0]
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				c.Bus.Brokers = append(c.Bus.Brokers, p)
			}
		}
	}
	// Single-device quick start: PROBECTL_DEVICE_TARGET=<address>, with
	// transport/credential/interval companions.
	if target := getenv("PROBECTL_DEVICE_TARGET"); target != "" {
		dev := Target{
			Address:    target,
			Transport:  strings.ToLower(getenv("PROBECTL_DEVICE_TRANSPORT")),
			Credential: getenv("PROBECTL_DEVICE_CREDENTIAL"),
		}
		if dev.Transport == "" {
			dev.Transport = TransportSNMPv2c
		}
		if v := getenv("PROBECTL_DEVICE_PORT"); v != "" {
			if n, err := strconv.ParseUint(v, 10, 16); err == nil {
				dev.Port = uint16(n)
			}
		}
		if v := getenv("PROBECTL_DEVICE_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 0 {
				dev.Interval = d
			}
		}
		c.Devices = append(c.Devices, dev)
	}
}

// Validate enforces the invariants the runtime depends on, and fills
// per-device defaults.
func (c *Config) Validate() error {
	if c.TenantID == "" {
		return errors.New("device: tenant_id is required (PROBECTL_DEVICE_TENANT)")
	}
	if len(c.Devices) == 0 {
		return errors.New("device: no devices configured")
	}
	for i := range c.Devices {
		d := &c.Devices[i]
		if d.Address == "" {
			return fmt.Errorf("device: devices[%d] has no address", i)
		}
		switch d.Transport {
		case TransportSNMPv2c, TransportSNMPv3:
			if d.Port == 0 {
				d.Port = 161
			}
			if d.Interval <= 0 {
				d.Interval = 60 * time.Second
			}
		case TransportGNMI:
			if d.Port == 0 {
				d.Port = 9339
			}
			if d.GNMI.SampleInterval <= 0 {
				d.GNMI.SampleInterval = 30 * time.Second
			}
			if len(d.GNMI.Paths) == 0 {
				d.GNMI.Paths = []string{
					"/interfaces/interface/state/counters",
					"/interfaces/interface/state/oper-status",
				}
			}
		default:
			return fmt.Errorf("device: devices[%d] (%s): unknown transport %q (want snmpv2c|snmpv3|gnmi)", i, d.Address, d.Transport)
		}
		if d.Credential == "" {
			return fmt.Errorf("device: devices[%d] (%s): credential name is required", i, d.Address)
		}
	}
	return nil
}
