// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
)

// PLAT-05: control-plane path discovery must apply the same deny-by-default
// SSRF guard as agent canaries. A test targeting a private/link-local/loopback
// address (or a hostname resolving to one) is refused at POST
// /v1/tests/{id}/path unless allow_private_targets=true is set on the test.
func TestPathDiscoveryRefusesPrivateTargets(t *testing.T) {
	h, _, disc := setupPathAPI(t)

	mkTest := func(target string, params map[string]string) store.Test {
		t.Helper()
		body := map[string]any{"name": fmt.Sprintf("ssrf-%d", time.Now().UnixNano()), "type": "icmp", "target": target}
		if params != nil {
			body["params"] = params
		}
		rec := apiReq(t, h, http.MethodPost, "/v1/tests", "", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create test %q = %d: %s", target, rec.Code, rec.Body)
		}
		var created store.Test
		mustJSON(t, rec, &created)
		return created
	}

	// Denied targets: the discoverer must never run.
	for _, target := range []string{"169.254.169.254", "10.0.0.1", "127.0.0.1", "localhost"} {
		ct := mkTest(target, nil)
		before := disc.calls
		rec := apiReq(t, h, http.MethodPost, "/v1/tests/"+ct.ID+"/path", "", nil)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("path discovery to %q = %d, want 403: %s", target, rec.Code, rec.Body)
		}
		if disc.calls != before {
			t.Fatalf("path discovery to %q ran the tracer (calls %d→%d)", target, before, disc.calls)
		}
	}

	// A public target still works (regression) and the tracer runs.
	pub := mkTest("9.9.9.9", nil)
	before := disc.calls
	if rec := apiReq(t, h, http.MethodPost, "/v1/tests/"+pub.ID+"/path", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("public path discovery = %d, want 200: %s", rec.Code, rec.Body)
	}
	if disc.calls != before+1 {
		t.Fatalf("public target: tracer calls %d→%d, want +1", before, disc.calls)
	}

	// The audited override lets a privileged operator probe a private target.
	priv := mkTest("10.10.0.5", map[string]string{"allow_private_targets": "true"})
	before = disc.calls
	if rec := apiReq(t, h, http.MethodPost, "/v1/tests/"+priv.ID+"/path", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("allow_private path discovery = %d, want 200: %s", rec.Code, rec.Body)
	}
	if disc.calls != before+1 {
		t.Fatalf("allow_private target: tracer calls %d→%d, want +1", before, disc.calls)
	}
}
