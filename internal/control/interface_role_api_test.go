// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"testing"
)

func TestInterfaceRoleConfigurationRoutesRequireSeparateReadAndWriteGrants(t *testing.T) {
	s := &Server{}
	want := map[string]string{
		"GET /v1/entity-contexts/{context_id}/interfaces/{id}/role":             "entities.read",
		"GET /v1/entity-contexts/{context_id}/interface-role-policy":            "entities.read",
		"PUT /v1/entity-contexts/{context_id}/interface-role-policy":            "agent.write",
		"GET /v1/entity-contexts/{context_id}/interfaces/{id}/role-override":    "entities.read",
		"PUT /v1/entity-contexts/{context_id}/interfaces/{id}/role-override":    "agent.write",
		"DELETE /v1/entity-contexts/{context_id}/interfaces/{id}/role-override": "agent.write",
	}
	for _, rt := range s.apiRoutes() {
		key := rt.Method + " " + rt.Pattern
		if grant, ok := want[key]; ok {
			if rt.Permission != grant || rt.Handler == nil {
				t.Fatalf("role configuration route lost its permission: %s", key)
			}
			policy, found := auditPolicyFor(rt.Method, rt.Pattern)
			if !found || !policy.active() || (rt.Method != http.MethodGet && policy.Mode != auditModeExplicit) {
				t.Fatalf("role configuration route lost atomic mutation audit: %s", key)
			}
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("role configuration routes are unavailable: %v", want)
	}
}
