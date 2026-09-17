// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/configschema"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/ebpf"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/flow"
)

// hintYAML renders the registration's YAML hints the way the UI, the code
// export and the CLI present them: one top-level key per line, a nested
// mapping nested (DPR-053).
func hintYAML(t *testing.T, hints map[string]any) []byte {
	t.Helper()
	keys := make([]string, 0, len(hints))
	for k := range hints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		switch v := hints[k].(type) {
		case string:
			fmt.Fprintf(&b, "%s: %q\n", k, v)
		case map[string]string:
			fmt.Fprintf(&b, "%s:\n", k)
			sub := make([]string, 0, len(v))
			for sk := range v {
				sub = append(sub, sk)
			}
			sort.Strings(sub)
			for _, sk := range sub {
				fmt.Fprintf(&b, "  %s: %q\n", sk, v[sk])
			}
		default:
			t.Fatalf("hint %q has type %T; the UI and CLI render strings and one-level mappings only", k, v)
		}
	}
	return []byte(b.String())
}

// TestCollectorConfigHintsAreRealCollectorKeys (DPR-053): every YAML hint the
// registration returns must be a key the collector's own strict loader
// accepts. DPR-049 first shipped a flat bus_namespace that no collector
// understood — every collector nests it as bus.namespace — and nothing
// loaded the hinted YAML into a real config.
func TestCollectorConfigHintsAreRealCollectorKeys(t *testing.T) {
	cases := []struct {
		plane, profile string
		into           func() any
		agentID        func(any) string
		lane           func(any) string
	}{
		{"flow", "", func() any { return &flow.Config{} },
			func(c any) string { return c.(*flow.Config).AgentID }, func(c any) string { return c.(*flow.Config).Bus.Namespace }},
		{"device", "standard", func() any { return &device.Config{} },
			func(c any) string { return c.(*device.Config).AgentID }, func(c any) string { return c.(*device.Config).Bus.Namespace }},
		{"endpoint", "", func() any { return &endpoint.Config{} },
			func(c any) string { return c.(*endpoint.Config).AgentID }, func(c any) string { return c.(*endpoint.Config).Bus.Namespace }},
		{"ebpf", "", func() any { return &ebpf.Config{} },
			func(c any) string { return c.(*ebpf.Config).AgentID }, func(c any) string { return c.(*ebpf.Config).Bus.Namespace }},
	}
	for _, tc := range cases {
		t.Run(tc.plane, func(t *testing.T) {
			h := collectorConfig(tc.plane, "tenant-a", "agent-a", tc.profile, "t-acme")
			raw := hintYAML(t, h.YAML)
			cfg := tc.into()
			if err := configschema.DecodeStrictYAML(raw, cfg); err != nil {
				t.Fatalf("%s hints are not accepted by the collector's strict loader:\n%serror: %v", tc.plane, raw, err)
			}
			if got := tc.agentID(cfg); got != "agent-a" {
				t.Fatalf("%s: agent_id did not reach the config (got %q):\n%s", tc.plane, got, raw)
			}
			if got := tc.lane(cfg); got != "t-acme" {
				t.Fatalf("%s: bus.namespace did not reach the config (got %q):\n%s", tc.plane, got, raw)
			}
		})
	}
}
