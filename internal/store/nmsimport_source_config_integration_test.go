// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

	var requests, deviceRequests, groupRequests, memberRequests atomic.Int32
	var drift, deviceDrift atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("source request lost its just-in-time bearer")
		}
		switch r.URL.EscapedPath() {
		case "/api/v0/devices":
			label := "Edge"
			if deviceRequests.Add(1)%2 == 0 && deviceDrift.Load() {
				label = "Edge changed"
			}
			_, _ = io.WriteString(w, fmt.Sprintf(`{"status":"ok","devices":[{"device_id":17,"display":%q,"ip":"10.0.0.1","community":"source-only-secret"}],"count":1}`, label))
		case "/api/v0/resources/locations":
			_, _ = io.WriteString(w, `{"status":"ok","locations":[{"id":5,"location":"West"}],"count":1}`)
		case "/api/v0/devicegroups":
			name := "WAN"
			if groupRequests.Add(1)%2 == 0 && drift.Load() {
				name = "WAN-renamed"
			}
			_, _ = io.WriteString(w, fmt.Sprintf(`[{"status":"ok","groups":[{"id":7,"name":%q}],"count":1}]`, name))
		case "/api/v0/rules":
			_, _ = io.WriteString(w, `{"status":"ok","rules":[{"id":9,"name":"Link down","rule":"source-only-rule"}],"count":1}`)
		case "/api/v0/devicegroups/WAN":
			memberRequests.Add(1)
			_, _ = io.WriteString(w, `[{"status":"ok","devices":[{"device_id":17}],"count":1}]`)
		default:
			t.Errorf("unlisted source path requested: %s", r.URL.EscapedPath())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "source-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	loopback := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if _, err := capturer.ConfigureLibreNMSHTTPSource(scopeA, contextID, "config-lab",
		server.URL, ref, prefix, loopback, caFile, time.Second); err != nil {
		t.Fatal(err)
	}
	currentPlan, err := capturer.StartPlan(scopeA, contextID, nmsimport.LibreNMS,
		"config-lab", strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capturer.AcquireConfiguredLibreNMSStage(scopeB, contextID, currentPlan); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("foreign tenant acquired live capture step: %v", err)
	}
	failAudit = true
	if _, err := capturer.AcquireConfiguredLibreNMSStage(scopeA, contextID, currentPlan); !errors.Is(err, auditFailure) {
		t.Fatalf("capture lease survived audit failure: %v", err)
	}
	failAudit = false
	step, err := capturer.AcquireConfiguredLibreNMSStage(scopeA, contextID, currentPlan)
	defer step.Zeroize()
	if err != nil || step.Stage != "devices" || step.GroupID != "" ||
		step.StartPage != 0 || step.StartRow != 0 {
		t.Fatalf("first live capture step: stage=%q group=%q page=%d row=%d err=%v",
			step.Stage, step.GroupID, step.StartPage, step.StartRow, err)
	}
	if _, err := capturer.AcquireConfiguredLibreNMSStage(scopeA, contextID, currentPlan); !errors.Is(err, nmsimport.ErrCaptureBusy) {
		t.Fatalf("parallel capture acquired the same step: %v", err)
	}
	if err := capturer.ReleaseConfiguredLibreNMSStage(scopeB, contextID, currentPlan, step); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("foreign tenant released capture lease: %v", err)
	}
	if err := capturer.ReleaseConfiguredLibreNMSStage(scopeA, contextID, currentPlan, step); err != nil {
		t.Fatalf("own capture lease release: %v", err)
	}
	step.Zeroize()
	retried, err := capturer.AcquireConfiguredLibreNMSStage(scopeA, contextID, currentPlan)
	defer retried.Zeroize()
	if err != nil || retried.Stage != "devices" || retried.StartPage != 0 {
		t.Fatalf("released capture step could not retry: stage=%q page=%d err=%v",
			retried.Stage, retried.StartPage, err)
	}
	if err := capturer.ReleaseConfiguredLibreNMSStage(scopeA, contextID, currentPlan, retried); err != nil {
		t.Fatal(err)
	}
	retried.Zeroize()
	resolver := &importSourceTokenResolver{}
	policy := nmsimport.LibreNMSFetchPolicy{ApprovedCIDRs: loopback, CAFile: caFile,
		AllowedRefPrefix: prefix, Resolver: resolver, Timeout: time.Second}
	if _, err := capturer.OpenConfiguredLibreNMS(scopeB, contextID, currentPlan,
		"devices", policy); !errors.Is(err, nmsimport.ErrPlanUnavailable) || requests.Load() != 0 || resolver.resolves != 0 {
		t.Fatalf("foreign tenant reached source: requests=%d resolves=%d err=%v", requests.Load(), resolver.resolves, err)
	}
	if _, err := capturer.OpenConfiguredLibreNMSMembership(scopeA, contextID,
		currentPlan, "7", policy); !errors.Is(err, nmsimport.ErrSourceUnavailable) || requests.Load() != 0 {
		t.Fatalf("uncaptured group reached source: requests=%d err=%v", requests.Load(), err)
	}
	failAudit = true
	if _, err := capturer.OpenConfiguredLibreNMS(scopeA, contextID, currentPlan,
		"devices", policy); !errors.Is(err, auditFailure) || requests.Load() != 0 {
		t.Fatalf("audit failure sent source request: requests=%d err=%v", requests.Load(), err)
	}
	failAudit = false
	group := `[ {"status":"ok","groups":[{"id":7,"name":"WAN"}],"count":1} ]`
	if _, err := capturer.AppendPage(scopeA, contextID, currentPlan, 0, "groups", 0,
		strings.NewReader(group)); err != nil {
		t.Fatal(err)
	}
	for _, read := range []func() (io.ReadCloser, error){
		func() (io.ReadCloser, error) {
			return capturer.OpenConfiguredLibreNMS(scopeA, contextID, currentPlan, "devices", policy)
		},
		func() (io.ReadCloser, error) {
			return capturer.OpenConfiguredLibreNMSMembership(scopeA, contextID, currentPlan, "7", policy)
		},
	} {
		body, err := read()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, body); err != nil {
			t.Fatal(err)
		}
		body.Close()
	}
	if requests.Load() != 2 || resolver.resolves != 2 || resolver.releases != 2 {
		t.Fatalf("tenant source requests or token leases lost: requests=%d resolver=%+v",
			requests.Load(), resolver)
	}
	livePlan, err := capturer.StartPlan(scopeA, contextID, nmsimport.LibreNMS,
		"config-lab", strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	if hash, err := capturer.CaptureConfiguredLibreNMSDevices(scopeA, contextID,
		livePlan, policy); err != nil || len(hash) != 64 {
		t.Fatalf("configured HTTPS response did not seal a tenant capture: hash=%q err=%v", hash, err)
	}
	if requests.Load() != 3 || resolver.resolves != 3 || resolver.releases != 3 {
		t.Fatalf("live capture lost its source request or token lease: requests=%d resolver=%+v",
			requests.Load(), resolver)
	}
	fullPlan, err := capturer.StartPlan(scopeA, contextID, nmsimport.LibreNMS,
		"config-lab", strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	if hash, err := capturer.CaptureConfiguredLibreNMSInventory(scopeA, contextID,
		fullPlan, policy); err != nil || len(hash) != 64 {
		t.Fatalf("configured five-resource capture did not seal: hash=%q err=%v", hash, err)
	}
	if err := tenancy.InTenant(scopeA, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var state string
		var rows int
		var leaked bool
		if err := sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans WHERE id=$1`, fullPlan).Scan(&state); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows WHERE plan_id=$1`, fullPlan).Scan(&rows); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nms_import_rows
			WHERE plan_id=$1 AND row_to_json(nms_import_rows)::text LIKE '%source-only-%')`, fullPlan).Scan(&leaked); err != nil {
			return err
		}
		if state != "sealed" || rows != 5 || leaked {
			return fmt.Errorf("live inventory lost rows or leaked source data: state=%s rows=%d leaked=%v", state, rows, leaked)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	firstRows, err := capturer.ListSealedRows(scopeA, contextID, fullPlan, -1, 2)
	if err != nil || firstRows.RowCount != 5 || len(firstRows.Items) != 2 ||
		firstRows.NextCursor == nil || len(firstRows.SnapshotHash) != 64 {
		t.Fatalf("sealed tenant rows did not page: page=%+v err=%v", firstRows, err)
	}
	secondRows, err := capturer.ListSealedRows(scopeA, contextID, fullPlan, *firstRows.NextCursor, 2)
	if err != nil || len(secondRows.Items) != 2 || secondRows.NextCursor == nil ||
		secondRows.Items[0].Number <= firstRows.Items[1].Number {
		t.Fatalf("sealed rows repeated or escaped page: page=%+v err=%v", secondRows, err)
	}
	lastRows, err := capturer.ListSealedRows(scopeA, contextID, fullPlan, *secondRows.NextCursor, 2)
	if err != nil || len(lastRows.Items) != 1 || lastRows.NextCursor != nil ||
		lastRows.Items[0].Number <= secondRows.Items[1].Number {
		t.Fatalf("sealed rows omitted final candidate: page=%+v err=%v", lastRows, err)
	}
	visible, err := json.Marshal([]nmsimport.SealedRowsPage{firstRows, secondRows, lastRows})
	if err != nil || strings.Contains(string(visible), "source-only-") {
		t.Fatalf("sealed row page copied secret or rule body: %v", err)
	}
	if _, err := capturer.ListSealedRows(scopeB, contextID, fullPlan, -1, 2); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("foreign tenant read sealed rows: %v", err)
	}
	if requests.Load() != 14 || resolver.resolves != 14 || resolver.releases != 14 {
		t.Fatalf("full source capture lost a fixed endpoint or token release: requests=%d resolver=%+v",
			requests.Load(), resolver)
	}
	stagedPlan, err := capturer.StartPlan(scopeA, contextID, nmsimport.LibreNMS,
		"config-lab", strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	beforeForeignAdvance := requests.Load()
	if _, err := capturer.CaptureNextConfiguredLibreNMSStage(scopeB, contextID,
		stagedPlan, policy); !errors.Is(err, nmsimport.ErrPlanUnavailable) ||
		requests.Load() != beforeForeignAdvance {
		t.Fatalf("foreign staged capture reached source: requests=%d err=%v", requests.Load(), err)
	}
	for i, stage := range []string{"devices", "locations", "groups", "memberships", "rules"} {
		progress, err := capturer.CaptureNextConfiguredLibreNMSStage(scopeA,
			contextID, stagedPlan, policy)
		if err != nil || progress.CompletedStage != stage || progress.Pages != 1 ||
			progress.Rows != 1 {
			t.Fatalf("staged endpoint %d: stage=%q pages=%d rows=%d err=%v",
				i, progress.CompletedStage, progress.Pages, progress.Rows, err)
		}
	}
	if err := tenancy.InTenant(scopeA, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var stage, state string
		var receipts, rows int
		if err := sc.Q.QueryRow(ctx, `SELECT capture_stage,state FROM nms_import_plans
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			a.ID, contextID, stagedPlan).Scan(&stage, &state); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_capture_steps
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
			a.ID, contextID, stagedPlan).Scan(&receipts); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows
			WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`,
			a.ID, contextID, stagedPlan).Scan(&rows); err != nil {
			return err
		}
		if stage != "verify_devices" || state != "capturing" || receipts != 5 || rows != 5 {
			return fmt.Errorf("staged inventory advanced without replay: stage=%s state=%s receipts=%d rows=%d",
				stage, state, receipts, rows)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	deviceDrift.Store(true)
	devicePlan, err := capturer.StartPlan(scopeA, contextID, nmsimport.LibreNMS,
		"config-lab", strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capturer.CaptureConfiguredLibreNMSInventory(scopeA, contextID,
		devicePlan, policy); !errors.Is(err, nmsimport.ErrInvalidPage) {
		t.Fatalf("source device changed between capture and replay: %v", err)
	}
	if err := tenancy.InTenant(scopeA, pool, func(ctx context.Context, sc tenancy.Scope) error {
		var state string
		if err := sc.Q.QueryRow(ctx, `SELECT state FROM nms_import_plans WHERE id=$1`, devicePlan).Scan(&state); err != nil {
			return err
		}
		if state != "capturing" {
			return fmt.Errorf("drifted source plan became actionable: %s", state)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	deviceDrift.Store(false)
	drift.Store(true)
	driftPlan, err := capturer.StartPlan(scopeA, contextID, nmsimport.LibreNMS,
		"config-lab", strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capturer.CaptureConfiguredLibreNMSInventory(scopeA, contextID,
		driftPlan, policy); !errors.Is(err, nmsimport.ErrInvalidPage) || memberRequests.Load() != 4 {
		t.Fatalf("renamed source group fetched a membership or sealed: members=%d err=%v",
			memberRequests.Load(), err)
	}
	requestsBeforeDisable := requests.Load()
	resolvesBeforeDisable := resolver.resolves
	if err := capturer.DisableLibreNMSHTTPSource(scopeB, contextID, "config-lab"); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("foreign tenant disabled source: %v", err)
	}
	failAudit = true
	if err := capturer.DisableLibreNMSHTTPSource(scopeA, contextID, "config-lab"); !errors.Is(err, auditFailure) {
		t.Fatalf("source disable survived audit failure: %v", err)
	}
	failAudit = false
	if err := capturer.DisableLibreNMSHTTPSource(scopeA, contextID, "config-lab"); err != nil {
		t.Fatal(err)
	}
	afterDisable := auditEvents
	if err := capturer.DisableLibreNMSHTTPSource(scopeA, contextID, "config-lab"); err != nil || auditEvents != afterDisable {
		t.Fatalf("idempotent disable duplicated audit: events=%d err=%v", auditEvents, err)
	}
	if _, err := capturer.OpenConfiguredLibreNMS(scopeA, contextID, currentPlan,
		"devices", policy); !errors.Is(err, nmsimport.ErrPlanUnavailable) || requests.Load() != requestsBeforeDisable || resolver.resolves != resolvesBeforeDisable {
		t.Fatalf("disabled source reached network or resolver: requests=%d resolves=%d err=%v",
			requests.Load(), resolver.resolves, err)
	}
}

type importSourceTokenResolver struct{ resolves, releases int }

func (r *importSourceTokenResolver) ResolveBytesUncached(context.Context, string) ([]byte, func(), error) {
	r.resolves++
	value := []byte("fixture")
	return value, func() {
		for i := range value {
			value[i] = 0
		}
		r.releases++
	}, nil
}
