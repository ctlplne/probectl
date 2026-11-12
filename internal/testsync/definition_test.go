// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsync

import (
	"maps"
	"testing"
)

func TestDefinitionHashKeepsExistingAgentBytesAndEveryExecutableField(t *testing.T) {
	original := Test{ID: "7fa4f1d1-b2a1-4bf5-98ce-782dbbd29f53", Type: "icmp", Target: "2001:db8::1", IntervalSeconds: 30, TimeoutSeconds: 5,
		Params: map[string]string{"payload_bytes": "4096", "count": "3"}}
	digest, err := DefinitionHash(original)
	if err != nil || digest != "02c72a7898f03dcf7ea1965eed10fb558ada0391d458fce87689b4d7580c58d2" {
		t.Fatal("the shared digest changed the existing agent's canonical definition", digest, err)
	}
	// Map insertion order is not a configuration change.
	equal := original
	equal.Params = map[string]string{"count": "3", "payload_bytes": "4096"}
	if got, err := DefinitionHash(equal); err != nil || got != digest {
		t.Fatal("equal definitions acquired different schedule identities", got, err)
	}
	mutations := map[string]func(*Test){
		"id":                func(v *Test) { v.ID = "0a93e22b-c36e-4af0-bdfe-b7a4fcdd6c75" },
		"type":              func(v *Test) { v.Type = "tcp" },
		"target":            func(v *Test) { v.Target = "2001:db8::2" },
		"interval":          func(v *Test) { v.IntervalSeconds++ },
		"timeout":           func(v *Test) { v.TimeoutSeconds++ },
		"parameter":         func(v *Test) { v.Params["payload_bytes"] = "65000" },
		"removed parameter": func(v *Test) { delete(v.Params, "count") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := original
			changed.Params = maps.Clone(original.Params)
			mutate(&changed)
			if got, err := DefinitionHash(changed); err != nil || got == digest {
				t.Fatal("changed executable definition reused old source evidence identity", got, err)
			}
		})
	}
}
