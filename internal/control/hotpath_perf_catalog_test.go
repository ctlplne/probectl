// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"fmt"
	"testing"

	"github.com/ctlplne/probectl/internal/perf"
)

// PERF-002: the user-visible hot-path SLO catalog must point at real served
// control-plane routes. A stale route in the catalog is worse than no target:
// operators would measure the wrong thing and think the product is healthy.
func TestHotPathCatalogControlRoutesExist(t *testing.T) {
	routes := map[string]bool{}
	for _, r := range (&Server{}).apiRoutes() {
		routes[fmt.Sprintf("%s %s", r.Method, r.Pattern)] = true
	}
	for _, hp := range perf.HotPathCatalog() {
		for _, s := range hp.Surfaces {
			if s.Kind != perf.SurfaceControlAPI {
				continue
			}
			key := fmt.Sprintf("%s %s", s.Method, s.Pattern)
			if !routes[key] {
				t.Errorf("%s: catalog surface %s is not mounted by the control-plane route table", hp.ID, key)
			}
		}
	}
}
