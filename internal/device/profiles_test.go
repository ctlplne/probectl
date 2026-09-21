// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCollectionProfilesExpandDeterministically(t *testing.T) {
	tests := []struct {
		profile       CollectionProfile
		snmpInterval  time.Duration
		sensors       bool
		neighbors     bool
		gnmiInterval  time.Duration
		gnmiPathCount int
	}{
		{CollectionProfileMinimal, 5 * time.Minute, false, false, 2 * time.Minute, 1},
		{CollectionProfileStandard, time.Minute, false, false, 30 * time.Second, 2},
		{CollectionProfileTopologyRich, time.Minute, true, true, 30 * time.Second, 2},
	}
	for _, tt := range tests {
		t.Run(string(tt.profile), func(t *testing.T) {
			cfg := &Config{
				TenantID:          "tenant-a",
				CollectionProfile: tt.profile,
				Devices: []Target{
					{Address: "192.0.2.10", Transport: TransportSNMPv3, Credential: "snmp-ro"},
					{Address: "192.0.2.11", Transport: TransportGNMI, Credential: "gnmi-ro"},
				},
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if got := cfg.Devices[0]; got.Interval != tt.snmpInterval ||
				got.Sensors != tt.sensors || got.Neighbors != tt.neighbors {
				t.Fatalf("SNMP expansion = %+v", got)
			}
			if got := cfg.Devices[1]; got.GNMI.SampleInterval != tt.gnmiInterval ||
				len(got.GNMI.Paths) != tt.gnmiPathCount {
				t.Fatalf("gNMI expansion = %+v", got.GNMI)
			}
			// Runtime construction validates a loaded config again. Expansion
			// must be idempotent rather than being mistaken for user conflict.
			if err := cfg.Validate(); err != nil {
				t.Fatalf("second validate: %v", err)
			}
		})
	}
}

func TestCollectionProfileExplicitOverridesAreBounded(t *testing.T) {
	path := writeDeviceConfig(t, `
apiVersion: probectl.io/device-agent/v1
tenant_id: tenant-a
collection_profile: topology-rich
devices:
  - address: 192.0.2.10
    transport: snmpv3
    credential: snmp-ro
    collection_overrides:
      interval: 90s
      sensors: false
      neighbors: false
  - address: 192.0.2.11
    transport: gnmi
    credential: gnmi-ro
    collection_overrides:
      gnmi_sample_interval: 45s
      gnmi_paths:
        - /interfaces/interface/state/oper-status
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.Devices[0]; got.Interval != 90*time.Second || got.Sensors || got.Neighbors {
		t.Fatalf("SNMP override = %+v", got)
	}
	if got := cfg.Devices[1].GNMI; got.SampleInterval != 45*time.Second ||
		len(got.Paths) != 1 || got.Paths[0] != defaultGNMIStatusPath {
		t.Fatalf("gNMI override = %+v", got)
	}
}

func TestCollectionProfileExpansionIsTransactional(t *testing.T) {
	cfg := &Config{
		TenantID:          "tenant-a",
		CollectionProfile: CollectionProfileTopologyRich,
		Devices: []Target{
			{Address: "192.0.2.10", Transport: TransportSNMPv3, Credential: "snmp-ro"},
			{
				Address:    "192.0.2.11",
				Transport:  TransportGNMI,
				Credential: "gnmi-ro",
				CollectionOverrides: CollectionOverrides{
					GNMIPaths: []string{"/vendor/private/state"},
				},
			},
		},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported profile gNMI path") {
		t.Fatalf("first validation error = %v", err)
	}
	if got := cfg.Devices[0]; got.Interval != 0 || got.Sensors || got.Neighbors {
		t.Fatalf("failed validation partially expanded first target: %+v", got)
	}
	if cfg.profileExpanded {
		t.Fatal("failed validation marked profile expanded")
	}

	cfg.Devices[1].CollectionOverrides.GNMIPaths = []string{defaultGNMIStatusPath}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validation after correction: %v", err)
	}
	if got := cfg.Devices[0]; got.Interval != time.Minute || !got.Sensors || !got.Neighbors {
		t.Fatalf("corrected config did not expand deterministically: %+v", got)
	}
}

func TestCollectionProfileRejectsUnknownAmbiguousAndUnsafeValues(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unknown",
			body: `
apiVersion: probectl.io/device-agent/v1
tenant_id: tenant-a
collection_profile: vendor-ultra
devices:
  - address: 192.0.2.10
    transport: snmpv3
    credential: snmp-ro
`,
			want: "unknown collection_profile",
		},
		{
			name: "legacy knob mixed with profile",
			body: `
apiVersion: probectl.io/device-agent/v1
tenant_id: tenant-a
collection_profile: topology-rich
devices:
  - address: 192.0.2.10
    transport: snmpv3
    credential: snmp-ro
    neighbors: false
`,
			want: "collection_profile conflicts with neighbors",
		},
		{
			name: "override without profile",
			body: `
apiVersion: probectl.io/device-agent/v1
tenant_id: tenant-a
devices:
  - address: 192.0.2.10
    transport: snmpv3
    credential: snmp-ro
    collection_overrides:
      interval: 90s
`,
			want: "collection_overrides requires collection_profile",
		},
		{
			name: "aggressive interval",
			body: `
apiVersion: probectl.io/device-agent/v1
tenant_id: tenant-a
collection_profile: standard
devices:
  - address: 192.0.2.10
    transport: snmpv3
    credential: snmp-ro
    collection_overrides:
      interval: 1s
`,
			want: "between 15s and 24h",
		},
		{
			name: "unknown gNMI path",
			body: `
apiVersion: probectl.io/device-agent/v1
tenant_id: tenant-a
collection_profile: standard
devices:
  - address: 192.0.2.11
    transport: gnmi
    credential: gnmi-ro
    collection_overrides:
      gnmi_paths:
        - /vendor/private/state
`,
			want: "unsupported profile gNMI path",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeDeviceConfig(t, tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestCollectionProfileKeepsLegacyConfigBackwardCompatible(t *testing.T) {
	cfg := &Config{
		TenantID: "tenant-a",
		Devices: []Target{{
			Address:    "192.0.2.10",
			Transport:  TransportSNMPv3,
			Credential: "snmp-ro",
			Interval:   45 * time.Second,
			Sensors:    true,
			Neighbors:  true,
		}},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("legacy validate: %v", err)
	}
	if got := cfg.Devices[0]; got.Interval != 45*time.Second || !got.Sensors || !got.Neighbors {
		t.Fatalf("legacy config changed = %+v", got)
	}
}

func TestCollectionProfileQuickStartEnvUsesExplicitOverrides(t *testing.T) {
	values := map[string]string{
		"PROBECTL_DEVICE_TENANT":     "tenant-a",
		"PROBECTL_DEVICE_PROFILE":    "topology-rich",
		"PROBECTL_DEVICE_TARGET":     "192.0.2.10",
		"PROBECTL_DEVICE_TRANSPORT":  "snmpv3",
		"PROBECTL_DEVICE_CREDENTIAL": "snmp-ro",
		"PROBECTL_DEVICE_INTERVAL":   "90s",
		"PROBECTL_DEVICE_SENSORS":    "false",
		"PROBECTL_DEVICE_NEIGHBORS":  "false",
	}
	cfg := Default()
	cfg.applyEnv(func(key string) string { return values[key] })
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got := cfg.Devices[0]; got.Interval != 90*time.Second || got.Sensors || got.Neighbors {
		t.Fatalf("quick-start override = %+v", got)
	}

	values["PROBECTL_DEVICE_INTERVAL"] = "as-fast-as-possible"
	bad := Default()
	bad.applyEnv(func(key string) string { return values[key] })
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "invalid profile override") {
		t.Fatalf("invalid env override error = %v", err)
	}
}

func TestEffectiveCollectionPreviewExcludesTenantAndCredential(t *testing.T) {
	cfg := &Config{
		TenantID:          "tenant-secret-id",
		CollectionProfile: CollectionProfileTopologyRich,
		Devices: []Target{{
			Address:    "192.0.2.10",
			Transport:  TransportSNMPv3,
			Credential: "credential-secret-name",
		}},
	}
	preview, err := cfg.EffectiveCollectionPreview()
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	raw, err := json.Marshal(preview)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, forbidden := range []string{"tenant-secret-id", "credential-secret-name"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("preview leaked %q: %s", forbidden, text)
		}
	}
	for _, required := range []string{
		`"profile":"topology-rich"`,
		`"network_requests_performed":false`,
		`"LLDP neighbors"`,
		`"CDP neighbors"`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("preview missing %q: %s", required, text)
		}
	}
}
