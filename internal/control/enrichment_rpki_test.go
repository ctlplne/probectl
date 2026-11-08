// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
)

func TestBuildRPKIEnrichmentKeepsLocalCompleteSourceAndUnavailableHealth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "validator.json")
	cfg := &config.Config{FlowEnrichRPKIFile: path, FlowEnrichRPKIMaxAge: time.Hour, FlowEnrichRPKIMemoryBytes: 2 << 30, FlowEnrichRPKIWorkUnits: 8 << 30, FlowEnrichCacheMax: 16}
	for _, body := range []string{"", `{"roas":[`, `{"roas":[]}`, fmt.Sprintf(`{"metadata":{"generated":%d},"roas":[]}`, time.Now().Add(-2*time.Hour).Unix())} {
		if body != "" {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		en, ok := BuildEnrichment(cfg, statusQuietLog())
		if !ok || len(en.Status()) != 1 || en.Status()[0].Health.Status != "unavailable" || en.RPKI(time.Now()).Current {
			t.Fatal("missing/partial/stale validator source was hidden or established authority", ok, en.Status())
		}
	}
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"metadata":{"generated":%d},"roas":[{"prefix":"192.0.2.0/24","maxLength":32,"asn":4294967295}]}`, time.Now().Unix())), 0o600); err != nil {
		t.Fatal(err)
	}
	en, ok := BuildEnrichment(cfg, statusQuietLog())
	if !ok || len(en.Status()) != 1 || en.Status()[0].Health.Status != "ok" {
		t.Fatal("local validator source was not registered independently", en.Status())
	}
	origin := ^uint32(0)
	verdict, proof, err := en.RPKI(time.Now()).Validate(t.Context(), netip.MustParsePrefix("192.0.2.0/25"), &origin, 1<<20, 1<<20)
	if err != nil || verdict != "valid" || len(proof) != 1 {
		t.Fatal("configured source lost complete original validator evidence", verdict, proof, err)
	}
}
