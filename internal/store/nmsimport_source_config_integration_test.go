// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// A source reconfiguration invalidates its old capture before any source body
// is consumed. The endpoint and reference are tenant-owned data below the API
// layer, and direct database writes cannot store env: as an apparent token.
func TestNMSImportSourceConfigTenantScopeAndPlanVersion(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "import-config-a-"+suffix, "Import config A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "import-config-b-"+suffix, "Import config B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove import config fixture tenants: %v", err)
		}
	})
	contextID := uuid.NewString()
	scopeA := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	scopeB := tenancy.WithTenant(ctx, tenancy.ID(b.ID))
	if err := tenancy.InTenant(scopeA, pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
			(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
			VALUES ($1,$2,$3,$4,'config site','config vrf')`,
			a.ID, contextID, uuid.NewString(), uuid.NewString())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	auditEvents := 0
	failAudit := false
	auditFailure := errors.New("source audit unavailable")
	capturer := nmsimport.NewCaptureStore(pool, func(_ context.Context, _ tenancy.Scope,
		_, _ string, details map[string]any) error {
		if _, leaked := details["credential_ref"]; leaked {
			return errors.New("source reference entered audit")
		}
		if failAudit {
			return auditFailure
		}
		auditEvents++
		return nil
	})
	planID, err := capturer.StartPlan(scopeA, contextID, nmsimport.LibreNMS,
		"config-lab", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	approved := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	const prefix = "vault:secret/probectl/nms/{tenant}/"
	ref := "vault:secret/probectl/nms/" + a.ID + "/api"
	if _, err := capturer.ConfigureLibreNMSHTTPSource(scopeB, contextID, "config-lab",
		"https://librenms.example", ref, prefix, approved, "", time.Second); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("foreign tenant configured source context: %v", err)
	}
	if _, err := capturer.ConfigureLibreNMSHTTPSource(scopeA, contextID, "config-lab",
		"https://librenms.example", "env:LOCAL", prefix, approved, "", time.Second); !errors.Is(err, nmsimport.ErrSourceUnavailable) {
		t.Fatalf("deployment environment reference accepted: %v", err)
	}
	sourceID, err := capturer.ConfigureLibreNMSHTTPSource(scopeA, contextID, "config-lab",
		"https://librenms.example", ref, prefix, approved, "", time.Second)
	if err != nil || sourceID == "" {
		t.Fatal(err)
	}
	if auditEvents != 2 {
		t.Fatalf("rejected configuration wrote an audit event: %d", auditEvents)
	}
	failAudit = true
	if _, err := capturer.ConfigureLibreNMSHTTPSource(scopeA, contextID, "config-lab",
		"https://changed.example", ref, prefix, approved, "", time.Second); !errors.Is(err, auditFailure) {
		t.Fatalf("source change survived audit failure: %v", err)
	}
	failAudit = false
	if err := tenancy.InTenant(scopeA, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var origin, storedRef string
		var enabled bool
		var version int64
		if err := sc.Q.QueryRow(ctx, `SELECT https_origin,credential_ref,fetch_enabled,config_version
			FROM nms_import_sources WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			a.ID, contextID, sourceID).Scan(&origin, &storedRef, &enabled, &version); err != nil {
			return err
		}
		if origin != "https://librenms.example" || storedRef != ref || !enabled || version != 1 {
			return errors.New("tenant source configuration was not committed exactly once")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(scopeB, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_sources
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextID, sourceID).
			Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return errors.New("foreign tenant read configured source")
		}
		updated, err := sc.Q.Exec(ctx, `UPDATE nms_import_sources
			SET fetch_enabled=false WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			a.ID, contextID, sourceID)
		if err != nil {
			return err
		}
		if updated.RowsAffected() != 0 {
			return errors.New("foreign tenant changed configured source")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InTenant(scopeA, pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE nms_import_sources SET credential_ref='env:LOCAL'
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextID, sourceID)
		return err
	}); err == nil {
		t.Fatal("direct database write stored a deployment environment reference")
	}
	reader := &observedImportReader{Reader: strings.NewReader(`{"status":"ok","devices":[]}`)}
	if _, err := capturer.CaptureLibreNMSDevices(scopeA, contextID, planID, reader); !errors.Is(err, nmsimport.ErrPlanUnavailable) || reader.reads != 0 {
		t.Fatalf("stale source configuration consumed body: reads=%d err=%v", reader.reads, err)
	}
	var state string
	if err := tenancy.InTenant(scopeA, pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextID, planID).
			Scan(&state)
	}); err != nil {
		t.Fatal(err)
	}
	if state != "capturing" {
		t.Fatalf("stale source plan became actionable: %s", state)
	}
}
