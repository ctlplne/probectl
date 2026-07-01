// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/notify"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// captureConnector records Open/Resolve calls (no HTTP), so the integration tests
// assert paging/ticketing + loop protection without a real provider.
type captureConnector struct {
	name    string
	cap     notify.Capability
	openRef string
	mu      sync.Mutex
	opens   int
	resolve []string
}

func (c *captureConnector) Name() string                  { return c.name }
func (c *captureConnector) Capability() notify.Capability { return c.cap }

func (c *captureConnector) Open(context.Context, incident.Incident) (notify.Delivery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.opens++
	ref := c.openRef
	if ref == "" {
		ref = c.name + "-ref"
	}
	return notify.Delivery{ExternalRef: ref, Status: "open"}, nil
}

func (c *captureConnector) Resolve(_ context.Context, _ incident.Incident, ref string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resolve = append(c.resolve, ref)
	return nil
}

func (c *captureConnector) opened() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.opens
}

func (c *captureConnector) resolved() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.resolve)
}

func drainNotify(t *testing.T, d *notify.Dispatcher, tenant string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := d.Drain(ctx, tenant); err != nil {
		t.Fatalf("drain notify dispatcher: %v", err)
	}
}

func openIncidentVia(t *testing.T, db *store.DB, d *notify.Dispatcher, tenant, target string) *incident.Incident {
	t.Helper()
	corr := BuildCorrelator(db.Pool(), time.Minute, logging.New(io.Discard, "error", "json"),
		incident.WithObserver(NotifyObserver(d, nil)))
	inc, err := corr.Ingest(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), incident.Signal{
		TenantID: tenant, Plane: "network", Kind: "alert.firing",
		Severity: incident.SeverityCritical, Title: "loss high on " + target, Target: target,
		OccurredAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	drainNotify(t, d, tenant)
	return inc
}

// An opened incident pages on-call + opens a ticket exactly once — a correlated
// follow-up signal does not re-page, and a redelivery (restart) is idempotent.
func TestIncidentOpenPagesAndTicketsIdempotent(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "notify-open")

	pd := &captureConnector{name: "pagerduty", cap: notify.CapabilityPager}
	sn := &captureConnector{name: "servicenow", cap: notify.CapabilityTicket, openRef: "sys-1"}
	d := notify.NewDispatcher(pgLinkStore{pool: db.Pool()}, logging.New(io.Discard, "error", "json"))
	d.Register(tenant, pd)
	d.Register(tenant, sn)

	inc := openIncidentVia(t, db, d, tenant, "10.0.0.9")
	if pd.opened() != 1 || sn.opened() != 1 {
		t.Fatalf("open should page+ticket once: pd=%d sn=%d", pd.opened(), sn.opened())
	}

	// A correlated follow-up (same target, within window) must NOT re-page.
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	d.Opened(ctx, *inc) // simulate a redelivery / restart re-emitting "opened"
	drainNotify(t, d, tenant)
	if pd.opened() != 1 || sn.opened() != 1 {
		t.Fatalf("redelivery must be idempotent: pd=%d sn=%d", pd.opened(), sn.opened())
	}

	// The link is persisted with the ticket's external ref.
	link, err := pgLinkStore{pool: db.Pool()}.Get(ctx, tenant, inc.ID, "servicenow")
	if err != nil || link == nil || link.ExternalRef != "sys-1" {
		t.Fatalf("link: %+v err=%v", link, err)
	}
}

func buildNotifyHandler(db *store.DB, d *notify.Dispatcher, inbound map[string]config.NotifyInbound) http.Handler {
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev", NotifyInbound: inbound, AIMaxEvidence: 50}
	return New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil).WithDispatcher(d).Handler()
}

func sign(secret string, body []byte) string {
	return "sha256=" + hex.EncodeToString(crypto.Sign([]byte(secret), body))
}

// An inbound ServiceNow "resolved" closes the incident and syncs the OTHER
// connectors, but is never echoed back to ServiceNow (loop protection). A forged
// delivery is rejected, and a duplicate is a no-op.
func TestInboundResolveSyncsAndLoopProtected(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "notify-inbound")

	pd := &captureConnector{name: "pagerduty", cap: notify.CapabilityPager}
	sn := &captureConnector{name: "servicenow", cap: notify.CapabilityTicket, openRef: "sys-1"}
	d := notify.NewDispatcher(pgLinkStore{pool: db.Pool()}, logging.New(io.Discard, "error", "json"))
	d.Register(tenant, pd)
	d.Register(tenant, sn)

	inc := openIncidentVia(t, db, d, tenant, "10.0.0.9") // opens links: servicenow=sys-1, pagerduty=pagerduty-ref

	secret := "shh-secret"
	h := buildNotifyHandler(db, d, map[string]config.NotifyInbound{
		"snow1": {TenantID: tenant, Provider: "servicenow", Secret: secret},
	})

	body := []byte(`{"sys_id":"sys-1","number":"INC1","state":"6"}`)

	// Forged (bad signature) → 401, no state change.
	bad := httptest.NewRequest(http.MethodPost, "/ingest/itsm/servicenow/snow1", bytes.NewReader(body))
	bad.Header.Set("X-Probectl-Signature", "sha256=deadbeef")
	br := httptest.NewRecorder()
	h.ServeHTTP(br, bad)
	if br.Code != http.StatusUnauthorized {
		t.Fatalf("forged inbound should be 401, got %d", br.Code)
	}

	// Valid signature → 202, incident resolved.
	ok := httptest.NewRequest(http.MethodPost, "/ingest/itsm/servicenow/snow1", bytes.NewReader(body))
	ok.Header.Set("X-Probectl-Signature", sign(secret, body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, ok)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("inbound resolve should be 202, got %d: %s", rec.Code, rec.Body)
	}
	drainNotify(t, d, tenant)

	// The incident is resolved.
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(c context.Context, sc tenancy.Scope) error {
		got, e := (store.Incidents{}).Get(c, sc, inc.ID)
		if e != nil {
			return e
		}
		if got.Status != incident.StatusResolved {
			t.Fatalf("incident should be resolved, got %q", got.Status)
		}
		return nil
	}); err != nil {
		t.Fatalf("get incident: %v", err)
	}

	// PagerDuty was synced; ServiceNow (the origin) was NOT echoed.
	if pd.resolved() != 1 {
		t.Fatalf("pagerduty should be resolved once, got %d", pd.resolved())
	}
	if sn.resolved() != 0 {
		t.Fatalf("servicenow must NOT be echoed (loop), got %d", sn.resolved())
	}

	// A duplicate inbound webhook is a no-op (incident already resolved).
	dup := httptest.NewRequest(http.MethodPost, "/ingest/itsm/servicenow/snow1", bytes.NewReader(body))
	dup.Header.Set("X-Probectl-Signature", sign(secret, body))
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, dup)
	drainNotify(t, d, tenant)
	if pd.resolved() != 1 {
		t.Fatalf("duplicate inbound must not re-resolve pagerduty, got %d", pd.resolved())
	}
}

// An inbound webhook for tenant A can never resolve tenant B's incident, even when
// both have a link with the same external ref (tenant-scoped reverse lookup).
func TestInboundTenantIsolation(t *testing.T) {
	db := changeDB(t)
	tenantA := freshTenant(t, db, "notify-a")
	tenantB := freshTenant(t, db, "notify-b")

	dB := notify.NewDispatcher(pgLinkStore{pool: db.Pool()}, logging.New(io.Discard, "error", "json"))
	snB := &captureConnector{name: "servicenow", cap: notify.CapabilityTicket, openRef: "shared-ref"}
	dB.Register(tenantB, snB)
	incB := openIncidentVia(t, db, dB, tenantB, "10.0.0.50") // tenant B link servicenow=shared-ref

	// Tenant A's inbound webhook posts the SAME external ref.
	secret := "a-secret"
	dA := notify.NewDispatcher(pgLinkStore{pool: db.Pool()}, logging.New(io.Discard, "error", "json"))
	h := buildNotifyHandler(db, dA, map[string]config.NotifyInbound{
		"a1": {TenantID: tenantA, Provider: "servicenow", Secret: secret},
	})
	body := []byte(`{"sys_id":"shared-ref","state":"6"}`)
	req := httptest.NewRequest(http.MethodPost, "/ingest/itsm/servicenow/a1", bytes.NewReader(body))
	req.Header.Set("X-Probectl-Signature", sign(secret, body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status: %d", rec.Code)
	}

	// Tenant B's incident must remain OPEN (A's webhook can't reach B's link).
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenantB))
	if err := tenancy.InTenant(ctx, db.Pool(), func(c context.Context, sc tenancy.Scope) error {
		got, e := (store.Incidents{}).Get(c, sc, incB.ID)
		if e != nil {
			return e
		}
		if got.Status != incident.StatusOpen {
			t.Fatalf("tenant B incident must stay open (cross-tenant leak!), got %q", got.Status)
		}
		return nil
	}); err != nil {
		t.Fatalf("get B incident: %v", err)
	}
}
