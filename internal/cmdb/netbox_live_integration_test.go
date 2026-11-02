//go:build integration

// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// This is a real source/provider proof, not the release-binary FX-3 receipt.
// Only its explicit CI step opts in; missing setup in that step fails.
func TestNetBoxLiveTenantMappingAndFreshPreview(t *testing.T) {
	if os.Getenv("PROBECTL_TEST_NETBOX_REQUIRED") != "1" {
		testsupport.SkipOptIn(t, "PROBECTL_TEST_NETBOX_REQUIRED", "real NetBox source proof is enabled in its dedicated CI step")
	}
	const runtime = "/tmp/probectl-qa-beta-netbox"
	path := os.Getenv("PROBECTL_TEST_NETBOX_FIXTURE")
	if path != runtime+"/manifest.json" {
		t.Fatal("required NetBox source fixture is absent or outside its owned runtime")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("required NetBox fixture manifest is unreadable")
	}
	var manifest struct {
		Origin    string            `json:"origin"`
		CAFile    string            `json:"ca_file"`
		TokenFile string            `json:"token_file"`
		Tenants   map[string]string `json:"tenants"`
		Devices   map[string]string `json:"devices"`
		IPs       map[string]string `json:"ips"`
	}
	if json.Unmarshal(raw, &manifest) != nil || manifest.Origin != "https://localhost:18443" ||
		manifest.CAFile != runtime+"/ca.crt" || manifest.TokenFile != runtime+"/token" {
		t.Fatal("invalid owned NetBox fixture manifest")
	}
	if manifest.Tenants["a"] == "" || manifest.Tenants["a"] == manifest.Tenants["b"] ||
		manifest.Devices["a"] == "" || manifest.Devices["a"] == manifest.Devices["b"] ||
		manifest.IPs["a"] == "" || manifest.IPs["a"] == manifest.IPs["b"] {
		t.Fatal("fixture did not seed distinct tenant, device and IP identities")
	}
	token, err := os.ReadFile(manifest.TokenFile)
	if err != nil {
		t.Fatal("required NetBox fixture credential is unreadable")
	}
	provider := NewNetBox(manifest.Origin, strings.TrimSpace(string(token)), map[string]string{
		netBoxTenantA: manifest.Tenants["a"], netBoxTenantB: manifest.Tenants["b"],
	})
	provider.client, err = crypto.HardenedHTTPClientWithCAFile(8*time.Second, manifest.CAFile)
	if err != nil {
		t.Fatal("required NetBox fixture CA is invalid")
	}
	t.Cleanup(provider.client.CloseIdleConnections)
	resolver := NewResolver(provider, time.Hour)
	callers := map[string]string{"a": netBoxTenantA, "b": netBoxTenantB}
	for _, lane := range []string{"a", "b", "a", "b"} {
		ctx := netBoxContext(callers[lane])
		for _, row := range []struct{ key, want string }{
			{"192.0.2.10", "netbox:ipam.ip_address:" + manifest.IPs[lane]},
			{"shared-edge", "netbox:dcim.device:" + manifest.Devices[lane]},
		} {
			cis, err := resolver.Lookup(ctx, row.key)
			if err != nil || len(cis) != 1 || cis[0].SysID != row.want {
				t.Fatalf("lane %s equal-key source lookup crossed or lost ownership: %v", lane, err)
			}
		}
		for _, field := range []string{"role", "site"} {
			candidate, err := resolver.PreviewNetBoxTag(ctx, "192.0.2.10", field)
			if err != nil || candidate.NetBoxTenantID != manifest.Tenants[lane] ||
				candidate.LookupCIID != "netbox:ipam.ip_address:"+manifest.IPs[lane] ||
				candidate.CIID != "netbox:dcim.device:"+manifest.Devices[lane] ||
				candidate.Name != "shared-edge" || candidate.Field != field || candidate.Value != field+"-"+lane ||
				candidate.SourceRef != fmt.Sprintf("netbox:t%s:ip%s:d%s:%s", manifest.Tenants[lane], manifest.IPs[lane], manifest.Devices[lane], field) {
				t.Fatalf("lane %s fresh %s preview did not attest the owned related CI: %v", lane, field, err)
			}
		}
	}
	for _, ctx := range []context.Context{t.Context(), netBoxContext("33333333-3333-4333-8333-333333333333")} {
		if cis, err := resolver.Lookup(ctx, "192.0.2.10"); !errors.Is(err, ErrTenantBinding) || len(cis) != 0 {
			t.Fatal("unmapped caller reached a warmed source lookup")
		}
		if candidate, err := resolver.PreviewNetBoxTag(ctx, "192.0.2.10", "role"); !errors.Is(err, ErrTenantBinding) || candidate != (NetBoxTagCandidate{}) {
			t.Fatal("unmapped caller reached a source preview")
		}
	}

	// Both lanes are warm. Changing the actual source must invalidate a new
	// import preview even though ordinary enrichment has a one-hour cache.
	t.Cleanup(func() { liveNetBoxMutation(t, "restore-ip", "a") })
	liveNetBoxMutation(t, "move-ip", "a", "b")
	for _, lane := range []string{"a", "b"} {
		candidate, err := resolver.PreviewNetBoxTag(netBoxContext(callers[lane]), "192.0.2.10", "role")
		if (!errors.Is(err, ErrNoTagCandidate) && !errors.Is(err, ErrTenantBinding)) || candidate != (NetBoxTagCandidate{}) {
			t.Fatalf("lane %s fresh preview trusted absent/ambiguous ownership after actual source change: %v", lane, err)
		}
	}
	if cis, err := resolver.Lookup(netBoxContext(netBoxTenantA), "192.0.2.10"); err != nil || len(cis) != 0 {
		t.Fatal("completed source ownership disappearance left the old enrichment cached")
	}
	proof := struct {
		Scope  string   `json:"scope"`
		Checks []string `json:"checks"`
	}{"real NetBox provider component; full FX-3 receipt remains required", []string{
		"equal private IPs and names remain tenant-bound through cache hits",
		"role and site require fresh full related-CI ownership",
		"missing tenant mapping refuses warmed cache and source preview",
		"actual source ownership move refuses fresh previews despite warm enrichment",
	}}
	encoded, err := json.MarshalIndent(proof, "", "  ")
	if err != nil || os.WriteFile(filepath.Join(runtime, "provider-proof.json"), append(encoded, '\n'), 0o600) != nil {
		t.Fatal("cannot persist the nonsecret source-provider receipt")
	}
}

func liveNetBoxMutation(t *testing.T, args ...string) {
	t.Helper()
	// A fresh cleanup context lets restoration run after t.Context is canceled.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "python3", append([]string{"../../scripts/ci_netbox.py"}, args...)...)
	if err := command.Run(); err != nil {
		t.Fatalf("owned NetBox source mutation/restore failed: %v", err)
	}
}
