// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package device

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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
	// Plaintext is retained only so legacy YAML fails with a precise validation
	// error. It is never honored: every gNMI channel requires verified TLS.
	Plaintext bool `yaml:"plaintext"`
}

// CollectionOverrides are the only collection-budget overrides accepted when
// collection_profile is active. Pointer booleans preserve an explicit false.
// Transport/security fields (address, port, credential, CA, plaintext) remain
// on Target because profiles do not own them.
type CollectionOverrides struct {
	Interval           time.Duration `yaml:"interval,omitempty"`
	Sensors            *bool         `yaml:"sensors,omitempty"`
	Neighbors          *bool         `yaml:"neighbors,omitempty"`
	GNMIPaths          []string      `yaml:"gnmi_paths,omitempty"`
	GNMISampleInterval time.Duration `yaml:"gnmi_sample_interval,omitempty"`
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
	// Neighbors enables the bounded, read-only LLDP/CDP MIB snapshot for this
	// explicitly configured SNMP target. It never scans for other devices.
	Neighbors bool       `yaml:"neighbors"`
	GNMI      GNMIConfig `yaml:"gnmi"`

	// CollectionOverrides intentionally separate profile changes from the
	// legacy collection knobs above. Mixing the two is rejected as ambiguous.
	CollectionOverrides CollectionOverrides `yaml:"collection_overrides,omitempty"`
}

// TrapSourceRef names one authenticated SNMP trap sender. Credential is a
// reference resolved through CredentialSource; the community/passphrases never
// live in config.
type TrapSourceRef struct {
	Name       string `yaml:"name"`
	Address    string `yaml:"address"`
	Transport  string `yaml:"transport"` // snmpv2c | snmpv3
	Credential string `yaml:"credential"`
}

// TrapConfig enables the inbound SNMP trap listener for the tenant-bound device
// agent. Traps are optional and fail closed unless every source has credentials.
type TrapConfig struct {
	Enabled bool            `yaml:"enabled"`
	Listen  string          `yaml:"listen"`
	Sources []TrapSourceRef `yaml:"sources"`
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

	// CollectionProfile selects one compiled evidence budget for every target.
	// Empty preserves the pre-profile explicit configuration behavior.
	CollectionProfile CollectionProfile `yaml:"collection_profile,omitempty"`

	// CorrelationRetention bounds the in-agent device/interface identity cache
	// used to enrich path/flow signals with sysName and interface labels.
	// 0 disables age pruning; default is 90 days.
	CorrelationRetention time.Duration `yaml:"correlation_retention"`

	Devices []Target   `yaml:"devices"`
	Traps   TrapConfig `yaml:"traps"`

	legacyCollectionFields map[int][]string
	profileExpanded        bool
	profileEnvErrors       []string
}

// Default returns the built-in defaults (memory bus, hostname agent id).
func Default() *Config {
	host, _ := os.Hostname()
	return &Config{AgentID: host, Bus: BusConfig{Mode: "memory"}, CorrelationRetention: 90 * 24 * time.Hour}
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
	if err := cfg.recordLegacyCollectionFields(raw); err != nil {
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
	if v := getenv("PROBECTL_DEVICE_PROFILE"); v != "" {
		c.CollectionProfile = CollectionProfile(v)
	}
	if v := getenv("PROBECTL_DEVICE_CORRELATION_RETENTION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= 0 {
			c.CorrelationRetention = d
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
				if c.CollectionProfile != "" {
					if dev.Transport == TransportGNMI {
						dev.CollectionOverrides.GNMISampleInterval = d
					} else {
						dev.CollectionOverrides.Interval = d
					}
				} else {
					dev.Interval = d
				}
			} else if c.CollectionProfile != "" {
				c.profileEnvErrors = append(c.profileEnvErrors, "PROBECTL_DEVICE_INTERVAL must be a positive duration")
			}
		}
		if v := getenv("PROBECTL_DEVICE_SENSORS"); v != "" {
			if enabled, err := strconv.ParseBool(v); err == nil {
				if c.CollectionProfile != "" {
					dev.CollectionOverrides.Sensors = &enabled
				} else {
					dev.Sensors = enabled
				}
			} else if c.CollectionProfile != "" {
				c.profileEnvErrors = append(c.profileEnvErrors, "PROBECTL_DEVICE_SENSORS must be true or false")
			}
		}
		if v := getenv("PROBECTL_DEVICE_NEIGHBORS"); v != "" {
			if enabled, err := strconv.ParseBool(v); err == nil {
				if c.CollectionProfile != "" {
					dev.CollectionOverrides.Neighbors = &enabled
				} else {
					dev.Neighbors = enabled
				}
			} else if c.CollectionProfile != "" {
				c.profileEnvErrors = append(c.profileEnvErrors, "PROBECTL_DEVICE_NEIGHBORS must be true or false")
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
	if len(c.profileEnvErrors) > 0 {
		return fmt.Errorf("device: invalid profile override: %s", strings.Join(c.profileEnvErrors, "; "))
	}
	if c.CorrelationRetention < 0 {
		return errors.New("device: correlation_retention must be >= 0")
	}
	if len(c.Devices) == 0 && !c.Traps.Enabled {
		return errors.New("device: no devices configured")
	}
	if err := c.Traps.validate(); err != nil {
		return err
	}
	var profile CollectionProfile
	if c.CollectionProfile != "" {
		var err error
		profile, err = ParseCollectionProfile(string(c.CollectionProfile))
		if err != nil {
			return err
		}
		c.CollectionProfile = profile
	}
	devices := c.Devices
	expandProfile := profile != "" && !c.profileExpanded
	if expandProfile {
		// Expand into a copy so one invalid later target cannot leave an
		// earlier target partially mutated after validation fails.
		devices = append([]Target(nil), c.Devices...)
	}
	for i := range devices {
		d := &devices[i]
		if d.Address == "" {
			return fmt.Errorf("device: devices[%d] has no address", i)
		}
		if profile == "" {
			if !d.CollectionOverrides.empty() {
				return fmt.Errorf(
					"device: devices[%d] (%s): collection_overrides requires collection_profile",
					i,
					d.Address,
				)
			}
		} else if expandProfile {
			if fields := c.legacyProfileFields(i, d); len(fields) > 0 {
				return fmt.Errorf(
					"device: devices[%d] (%s): collection_profile conflicts with %s; move collection-budget changes under collection_overrides",
					i,
					d.Address,
					strings.Join(fields, ", "),
				)
			}
			if err := applyCollectionProfile(d, profile, i); err != nil {
				return err
			}
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
			if d.Neighbors {
				return fmt.Errorf("device: devices[%d] (%s): neighbors requires an SNMP transport", i, d.Address)
			}
			if d.GNMI.Plaintext {
				return fmt.Errorf("device: devices[%d] (%s): gnmi.plaintext is forbidden; verified TLS is required", i, d.Address)
			}
			if d.Port == 0 {
				d.Port = 9339
			}
			if d.GNMI.SampleInterval <= 0 {
				d.GNMI.SampleInterval = 30 * time.Second
			}
			if len(d.GNMI.Paths) == 0 {
				d.GNMI.Paths = []string{
					defaultGNMICountersPath,
					defaultGNMIStatusPath,
				}
			}
		default:
			return fmt.Errorf("device: devices[%d] (%s): unknown transport %q (want snmpv2c|snmpv3|gnmi)", i, d.Address, d.Transport)
		}
		if d.Credential == "" {
			return fmt.Errorf("device: devices[%d] (%s): credential name is required", i, d.Address)
		}
	}
	if expandProfile {
		c.Devices = devices
		c.profileExpanded = true
	}
	return nil
}

func (o CollectionOverrides) empty() bool {
	return o.Interval == 0 &&
		o.Sensors == nil &&
		o.Neighbors == nil &&
		len(o.GNMIPaths) == 0 &&
		o.GNMISampleInterval == 0
}

func (c *Config) legacyProfileFields(index int, d *Target) []string {
	fields := append([]string(nil), c.legacyCollectionFields[index]...)
	if len(fields) > 0 {
		return fields
	}
	if d.Interval != 0 {
		fields = append(fields, "interval")
	}
	if d.Sensors {
		fields = append(fields, "sensors")
	}
	if d.Neighbors {
		fields = append(fields, "neighbors")
	}
	if d.GNMI.SampleInterval != 0 {
		fields = append(fields, "gnmi.sample_interval")
	}
	if len(d.GNMI.Paths) > 0 {
		fields = append(fields, "gnmi.paths")
	}
	return fields
}

func applyCollectionProfile(d *Target, profile CollectionProfile, index int) error {
	plan, ok := planForCollectionProfile(profile)
	if !ok {
		return fmt.Errorf("device: devices[%d]: invalid collection profile %q", index, profile)
	}
	o := d.CollectionOverrides
	switch d.Transport {
	case TransportSNMPv2c, TransportSNMPv3:
		if o.GNMISampleInterval != 0 || len(o.GNMIPaths) > 0 {
			return fmt.Errorf(
				"device: devices[%d] (%s): gNMI collection overrides require transport gnmi",
				index,
				d.Address,
			)
		}
		d.Interval = plan.snmpInterval
		d.Sensors = plan.sensors
		d.Neighbors = plan.neighbors
		if o.Interval != 0 {
			if o.Interval < 15*time.Second || o.Interval > 24*time.Hour {
				return fmt.Errorf(
					"device: devices[%d] (%s): collection_overrides.interval must be between 15s and 24h",
					index,
					d.Address,
				)
			}
			d.Interval = o.Interval
		}
		if o.Sensors != nil {
			d.Sensors = *o.Sensors
		}
		if o.Neighbors != nil {
			d.Neighbors = *o.Neighbors
		}
	case TransportGNMI:
		if o.Interval != 0 || o.Sensors != nil || o.Neighbors != nil {
			return fmt.Errorf(
				"device: devices[%d] (%s): SNMP collection overrides require transport snmpv2c or snmpv3",
				index,
				d.Address,
			)
		}
		d.GNMI.SampleInterval = plan.gnmiSampleInterval
		d.GNMI.Paths = append([]string(nil), plan.gnmiPaths...)
		if o.GNMISampleInterval != 0 {
			if o.GNMISampleInterval < 5*time.Second || o.GNMISampleInterval > time.Hour {
				return fmt.Errorf(
					"device: devices[%d] (%s): collection_overrides.gnmi_sample_interval must be between 5s and 1h",
					index,
					d.Address,
				)
			}
			d.GNMI.SampleInterval = o.GNMISampleInterval
		}
		if len(o.GNMIPaths) > 0 {
			if len(o.GNMIPaths) > 2 {
				return fmt.Errorf(
					"device: devices[%d] (%s): collection_overrides.gnmi_paths exceeds the two compiled paths",
					index,
					d.Address,
				)
			}
			seen := make(map[string]struct{}, len(o.GNMIPaths))
			for _, path := range o.GNMIPaths {
				if !supportedProfileGNMIPath(path) {
					return fmt.Errorf(
						"device: devices[%d] (%s): unsupported profile gNMI path %q",
						index,
						d.Address,
						path,
					)
				}
				if _, duplicate := seen[path]; duplicate {
					return fmt.Errorf(
						"device: devices[%d] (%s): duplicate profile gNMI path %q",
						index,
						d.Address,
						path,
					)
				}
				seen[path] = struct{}{}
			}
			d.GNMI.Paths = append([]string(nil), o.GNMIPaths...)
		}
	default:
		// The established transport validator below returns the canonical error.
	}
	return nil
}

func (c *Config) recordLegacyCollectionFields(raw []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return err
	}
	c.legacyCollectionFields = make(map[int][]string)
	if len(doc.Content) == 0 || len(doc.Content[0].Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "devices" {
			continue
		}
		devices := root.Content[i+1]
		if devices.Kind != yaml.SequenceNode {
			return nil
		}
		for index, target := range devices.Content {
			if target.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(target.Content); j += 2 {
				key, value := target.Content[j].Value, target.Content[j+1]
				switch key {
				case "interval", "sensors", "neighbors":
					c.legacyCollectionFields[index] = append(c.legacyCollectionFields[index], key)
				case "gnmi":
					if value.Kind != yaml.MappingNode {
						continue
					}
					for k := 0; k+1 < len(value.Content); k += 2 {
						switch value.Content[k].Value {
						case "paths", "sample_interval":
							c.legacyCollectionFields[index] = append(
								c.legacyCollectionFields[index],
								"gnmi."+value.Content[k].Value,
							)
						}
					}
				}
			}
		}
	}
	return nil
}

func (t *TrapConfig) validate() error {
	if !t.Enabled {
		return nil
	}
	if t.Listen == "" {
		t.Listen = ":9162"
	}
	if len(t.Sources) == 0 {
		return errors.New("device: traps.sources requires at least one authenticated source")
	}
	for i := range t.Sources {
		src := &t.Sources[i]
		if src.Name == "" {
			return fmt.Errorf("device: traps.sources[%d] name is required", i)
		}
		if src.Transport == "" {
			src.Transport = TransportSNMPv2c
		}
		if src.Transport != TransportSNMPv2c && src.Transport != TransportSNMPv3 {
			return fmt.Errorf("device: traps.sources[%d] (%s): unknown transport %q (want snmpv2c|snmpv3)", i, src.Name, src.Transport)
		}
		if src.Credential == "" {
			return fmt.Errorf("device: traps.sources[%d] (%s): credential name is required", i, src.Name)
		}
	}
	return nil
}
