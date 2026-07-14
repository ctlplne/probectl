// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import "testing"

func TestAuditPolicyMatrixCoversRequiredRoutes(t *testing.T) {
	routes := testServer(nil).apiRoutes()
	seen := map[string]bool{}
	for _, rt := range routes {
		key := routeKey(rt.Method, rt.Pattern)
		seen[key] = true
		required, ok := auditRequiredFacet(rt.Method, rt.Pattern)
		if !ok {
			if p, found := auditPolicyFor(rt.Method, rt.Pattern); found && p.active() {
				t.Fatalf("%s has audit policy %+v but is classified as exempt", key, p)
			}
			continue
		}
		p, found := auditPolicyFor(rt.Method, rt.Pattern)
		if !found || !p.active() {
			t.Fatalf("%s requires a %s audit event but has no wrapper or explicit audit path", key, required)
		}
		if p.Facet != required {
			t.Fatalf("%s audit facet = %s, want %s", key, p.Facet, required)
		}
		if p.Action == "" || p.Target == "" {
			t.Fatalf("%s audit policy is missing action/target: %+v", key, p)
		}
	}
	for key := range auditPolicyMatrix {
		if !seen[key] {
			t.Fatalf("audit policy matrix references unregistered route %s", key)
		}
	}
}
