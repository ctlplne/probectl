// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"fmt"
	"strconv"
	"time"
)

// CollectionProfile is the stable, compiled evidence-budget vocabulary.
// Profiles only select collectors already implemented by this package.
type CollectionProfile string

const (
	CollectionProfileMinimal      CollectionProfile = "minimal"
	CollectionProfileStandard     CollectionProfile = "standard"
	CollectionProfileTopologyRich CollectionProfile = "topology-rich"

	DefaultCollectionProfile = CollectionProfileStandard

	defaultGNMICountersPath = "/interfaces/interface/state/counters"
	defaultGNMIStatusPath   = "/interfaces/interface/state/oper-status"
)

var baseSNMPWalks = []string{
	"system identity and uptime",
	"interface identity and status",
	"interface counters",
	"interface addresses",
	"host CPU and memory",
}

type collectionProfilePlan struct {
	name               CollectionProfile
	description        string
	snmpInterval       time.Duration
	sensors            bool
	neighbors          bool
	gnmiSampleInterval time.Duration
	gnmiPaths          []string
}

var collectionProfilePlans = []collectionProfilePlan{
	{
		name:               CollectionProfileMinimal,
		description:        "Lower-frequency base health with no optional sensor or neighbor walks.",
		snmpInterval:       5 * time.Minute,
		gnmiSampleInterval: 2 * time.Minute,
		gnmiPaths:          []string{defaultGNMIStatusPath},
	},
	{
		name:               CollectionProfileStandard,
		description:        "Balanced interface, host-health, and OpenConfig counter evidence.",
		snmpInterval:       time.Minute,
		gnmiSampleInterval: 30 * time.Second,
		gnmiPaths:          []string{defaultGNMICountersPath, defaultGNMIStatusPath},
	},
	{
		name:               CollectionProfileTopologyRich,
		description:        "Standard evidence plus SNMP temperature and bounded LLDP/CDP adjacency walks.",
		snmpInterval:       time.Minute,
		sensors:            true,
		neighbors:          true,
		gnmiSampleInterval: 30 * time.Second,
		gnmiPaths:          []string{defaultGNMICountersPath, defaultGNMIStatusPath},
	},
}

// CollectionProfileSummary is the credential-free, transport-specific catalog
// shown by local CLIs and the native setup surface.
type CollectionProfileSummary struct {
	Name               CollectionProfile `json:"name"`
	Description        string            `json:"description"`
	SNMPInterval       string            `json:"snmp_interval"`
	SNMPWalks          []string          `json:"snmp_walks"`
	GNMISampleInterval string            `json:"gnmi_sample_interval"`
	GNMIPaths          []string          `json:"gnmi_paths"`
}

// CollectionPreview is the effective, credential-free answer produced before
// agent startup. It deliberately carries neither tenant identity nor credential
// names/material and performs no network request.
type CollectionPreview struct {
	Profile                  string                    `json:"profile"`
	Targets                  []TargetCollectionPreview `json:"targets"`
	TrapListenerEnabled      bool                      `json:"trap_listener_enabled"`
	NetworkRequestsPerformed bool                      `json:"network_requests_performed"`
	Safety                   []string                  `json:"safety"`
}

// TargetCollectionPreview describes the exact cadence and bounded reads for one
// explicitly configured target.
type TargetCollectionPreview struct {
	Index       int      `json:"index"`
	Address     string   `json:"address"`
	Transport   string   `json:"transport"`
	Cadence     string   `json:"cadence"`
	SNMPWalks   []string `json:"snmp_walks,omitempty"`
	GNMIPaths   []string `json:"gnmi_paths,omitempty"`
	Sensors     bool     `json:"sensors,omitempty"`
	Neighbors   bool     `json:"neighbors,omitempty"`
	Description string   `json:"description"`
}

// CollectionProfileCatalog returns defensive copies in stable display order.
func CollectionProfileCatalog() []CollectionProfileSummary {
	out := make([]CollectionProfileSummary, 0, len(collectionProfilePlans))
	for _, plan := range collectionProfilePlans {
		walks := append([]string(nil), baseSNMPWalks...)
		if plan.sensors {
			walks = append(walks, "entity temperature sensors")
		}
		if plan.neighbors {
			walks = append(walks, "LLDP neighbors", "CDP neighbors")
		}
		out = append(out, CollectionProfileSummary{
			Name:               plan.name,
			Description:        plan.description,
			SNMPInterval:       collectionDurationLabel(plan.snmpInterval),
			SNMPWalks:          walks,
			GNMISampleInterval: collectionDurationLabel(plan.gnmiSampleInterval),
			GNMIPaths:          append([]string(nil), plan.gnmiPaths...),
		})
	}
	return out
}

// EffectiveCollectionPreview validates and expands the config, then returns a
// redacted preview. Validation happens before any runtime or secret resolver is
// constructed, so a bad profile cannot cause a network request.
func (c *Config) EffectiveCollectionPreview() (CollectionPreview, error) {
	if err := c.Validate(); err != nil {
		return CollectionPreview{}, err
	}
	profile := string(c.CollectionProfile)
	if profile == "" {
		profile = "explicit"
	}
	out := CollectionPreview{
		Profile:             profile,
		TrapListenerEnabled: c.Traps.Enabled,
		Safety: []string{
			"configured targets only",
			"read-only collection",
			"no subnet discovery",
			"no credential probing",
			"no device mutation",
			"no vendor cloud",
		},
	}
	for i, target := range c.Devices {
		preview := TargetCollectionPreview{
			Index:       i,
			Address:     target.Address,
			Transport:   target.Transport,
			Description: "compiled local collectors only",
		}
		switch target.Transport {
		case TransportSNMPv2c, TransportSNMPv3:
			preview.Cadence = collectionDurationLabel(target.Interval)
			preview.SNMPWalks = append([]string(nil), baseSNMPWalks...)
			preview.Sensors = target.Sensors
			preview.Neighbors = target.Neighbors
			if target.Sensors {
				preview.SNMPWalks = append(preview.SNMPWalks, "entity temperature sensors")
			}
			if target.Neighbors {
				preview.SNMPWalks = append(preview.SNMPWalks, "LLDP neighbors", "CDP neighbors")
			}
		case TransportGNMI:
			preview.Cadence = collectionDurationLabel(target.GNMI.SampleInterval)
			preview.GNMIPaths = append([]string(nil), target.GNMI.Paths...)
		}
		out.Targets = append(out.Targets, preview)
	}
	return out, nil
}

// ParseCollectionProfile rejects every value outside the compiled vocabulary.
func ParseCollectionProfile(raw string) (CollectionProfile, error) {
	for _, plan := range collectionProfilePlans {
		if raw == string(plan.name) {
			return plan.name, nil
		}
	}
	return "", fmt.Errorf(
		"device: unknown collection_profile %q (want minimal|standard|topology-rich)",
		raw,
	)
}

func planForCollectionProfile(profile CollectionProfile) (collectionProfilePlan, bool) {
	for _, plan := range collectionProfilePlans {
		if plan.name == profile {
			plan.gnmiPaths = append([]string(nil), plan.gnmiPaths...)
			return plan, true
		}
	}
	return collectionProfilePlan{}, false
}

func supportedProfileGNMIPath(path string) bool {
	return path == defaultGNMICountersPath || path == defaultGNMIStatusPath
}

func collectionDurationLabel(duration time.Duration) string {
	if duration > 0 && duration%time.Minute == 0 {
		return strconv.FormatInt(int64(duration/time.Minute), 10) + "m"
	}
	return duration.String()
}
