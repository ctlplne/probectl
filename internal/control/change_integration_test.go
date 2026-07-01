// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/change"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func changeDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, integrationDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		t.Skipf("no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		db.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func buildChangeHandler(db *store.DB, webhooks map[string]config.ChangeWebhook) http.Handler {
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev",
		ChangeWebhooks: webhooks, ChangeCorrelationWindow: 24 * time.Hour, AIMaxEvidence: 50}
	return New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil).Handler()
}

func freshTenant(t *testing.T, db *store.DB, prefix string) string {
	t.Helper()
	tn, err := store.NewTenants(db.Pool()).Create(context.Background(),
		fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()), prefix)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn.ID
}

func seedChange(t *testing.T, db *store.DB, tenant string, ev change.Event) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, e := store.ChangeEvents{}.Create(ctx, sc, ev)
		return e
	}); err != nil {
		t.Fatalf("seed change: %v", err)
	}
}

func postWebhook(t *testing.T, h http.Handler, provider, id string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/ingest/changes/"+provider+"/"+id, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func hmacSig(secret string, body []byte) string {
	return "sha256=" + hex.EncodeToString(crypto.Sign([]byte(secret), body))
}

func genericSig(secret, timestamp string, body []byte) string {
	payload := make([]byte, 0, len(timestamp)+1+len(body))
	payload = append(payload, timestamp...)
	payload = append(payload, '.')
	payload = append(payload, body...)
	return "sha256=" + hex.EncodeToString(crypto.Sign([]byte(secret), payload))
}

func signedGenericHeaders(secret string, body []byte, deliveryID string, now time.Time) map[string]string {
	ts := strconv.FormatInt(now.Unix(), 10)
	return map[string]string{
		change.GenericDeliveryIDHeader: deliveryID,
		change.GenericTimestampHeader:  ts,
		change.GenericSignatureHeader:  genericSig(secret, ts, body),
	}
}

func countTenantRows(t *testing.T, db *store.DB, tenant, sql string, args ...any) int {
	t.Helper()
	var n int
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatalf("count tenant rows: %v", err)
	}
	return n
}

// A validly-signed delivery is accepted, normalized, and lands on the tenant's
// change timeline.
func TestChangeWebhookIngestAndTimeline(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "chg")
	id, secret := "wh-"+tenant[:8], "topsecret-"+tenant[:8]
	h := buildChangeHandler(db, map[string]config.ChangeWebhook{id: {TenantID: tenant, Provider: "generic", Secret: secret}})

	body := []byte(`{"kind":"deploy","title":"deploy payments-api to prod","target":"api.example.com","actor":"ci"}`)
	rec := postWebhook(t, h, "generic", id, body, signedGenericHeaders(secret, body, "delivery-"+tenant[:8], time.Now().UTC()))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	rec = apiReq(t, h, http.MethodGet, "/v1/changes", tenant, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "deploy payments-api to prod") {
		t.Fatalf("timeline missing the ingested change: %d %s", rec.Code, rec.Body)
	}
}

// Unsigned, forged, and unknown-id deliveries are rejected and never persisted —
// a forged change event cannot reach the timeline or RCA (guardrail 12).
func TestChangeWebhookRejectsUnsignedAndForged(t *testing.T) {
	db := changeDB(t)
	tenant := freshTenant(t, db, "chgsec")
	id, secret := "wh-"+tenant[:8], "realsecret"
	h := buildChangeHandler(db, map[string]config.ChangeWebhook{id: {TenantID: tenant, Provider: "generic", Secret: secret}})
	body := []byte(`{"title":"sneaky deploy","target":"api.example.com"}`)

	if rec := postWebhook(t, h, "generic", id, body, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("unsigned: code = %d, want 401", rec.Code)
	}
	if rec := postWebhook(t, h, "generic", id, body, signedGenericHeaders("wrong-secret", body, "forged-"+tenant[:8], time.Now().UTC())); rec.Code != http.StatusUnauthorized {
		t.Errorf("forged: code = %d, want 401", rec.Code)
	}
	if rec := postWebhook(t, h, "generic", "no-such-id", body, signedGenericHeaders(secret, body, "unknown-"+tenant[:8], time.Now().UTC())); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown id: code = %d, want 401", rec.Code)
	}
	if rec := apiReq(t, h, http.MethodGet, "/v1/changes", tenant, nil); rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "sneaky deploy") {
		t.Errorf("a rejected delivery must not persist: %s", rec.Body)
	}
}

// One tenant cannot inject another tenant's change events: the event's tenant is
// bound to the verified credential (never the payload), and a delivery to another
// tenant's webhook fails its HMAC.
func TestChangeWebhookTenantIsolation(t *testing.T) {
	db := changeDB(t)
	tenantA := freshTenant(t, db, "chgA")
	tenantB := freshTenant(t, db, "chgB")
	idA, secretA := "whA-"+tenantA[:8], "secretA"
	idB, secretB := "whB-"+tenantB[:8], "secretB"
	h := buildChangeHandler(db, map[string]config.ChangeWebhook{
		idA: {TenantID: tenantA, Provider: "generic", Secret: secretA},
		idB: {TenantID: tenantB, Provider: "generic", Secret: secretB},
	})

	body := []byte(`{"title":"A-only deploy","target":"a.example.com"}`)
	if rec := postWebhook(t, h, "generic", idA, body, signedGenericHeaders(secretA, body, "delivery-"+tenantA[:8], time.Now().UTC())); rec.Code != http.StatusAccepted {
		t.Fatalf("A ingest: %d %s", rec.Code, rec.Body)
	}
	if rec := apiReq(t, h, http.MethodGet, "/v1/changes", tenantA, nil); !strings.Contains(rec.Body.String(), "A-only deploy") {
		t.Errorf("A should see its own change: %s", rec.Body)
	}
	if rec := apiReq(t, h, http.MethodGet, "/v1/changes", tenantB, nil); strings.Contains(rec.Body.String(), "A-only deploy") {
		t.Errorf("B must NOT see A's change: %s", rec.Body)
	}
	// B signs with its own secret but targets A's webhook → HMAC fails → rejected.
	if rec := postWebhook(t, h, "generic", idA, body, signedGenericHeaders(secretB, body, "cross-"+tenantA[:8], time.Now().UTC())); rec.Code != http.StatusUnauthorized {
		t.Errorf("cross-tenant injection must be rejected: code = %d", rec.Code)
	}
}

// Replaying the exact same signed provider delivery is an idempotent success:
// the delivery receipt is updated, but no second change event or audit row is
// appended.
func TestChangeWebhookDeduplicatesSignedDeliveries(t *testing.T) {
	db := changeDB(t)
	now := time.Now().UTC().Truncate(time.Second)

	cases := []struct {
		name     string
		provider string
		body     []byte
		headers  func(secret, tenant string, body []byte) map[string]string
	}{
		{
			name:     "generic",
			provider: "generic",
			body:     []byte(`{"kind":"deploy","title":"dedupe generic deploy","target":"api.example.com","actor":"ci"}`),
			headers: func(secret, tenant string, body []byte) map[string]string {
				return signedGenericHeaders(secret, body, "generic-delivery-"+tenant[:8], now)
			},
		},
		{
			name:     "github",
			provider: "github",
			body: []byte(`{"ref":"refs/heads/main","compare":"https://github.example/acme/shop/compare","pusher":{"name":"alice"},
				"repository":{"full_name":"acme/shop"},"head_commit":{"id":"deadbeef","message":"fix checkout","url":"https://github.example/acme/shop/commit/deadbeef","timestamp":"` + now.Format(time.RFC3339) + `"},
				"commits":[{"id":"deadbeef"}]}`),
			headers: func(secret, tenant string, body []byte) map[string]string {
				return map[string]string{
					change.GitHubDeliveryHeader:  "github-delivery-" + tenant[:8],
					change.GitHubSignatureHeader: hmacSig(secret, body),
					"X-GitHub-Event":             "push",
				}
			},
		},
		{
			name:     "gitlab",
			provider: "gitlab",
			body: []byte(`{"ref":"refs/heads/main","user_name":"carol","checkout_sha":"99aa",
				"project":{"path_with_namespace":"team/svc","web_url":"https://gitlab.example/team/svc"},
				"commits":[{"message":"bump","url":"https://gitlab.example/team/svc/-/commit/99aa"}]}`),
			headers: func(secret, tenant string, _ []byte) map[string]string {
				return map[string]string{
					change.GitLabEventUUIDHeader: "gitlab-delivery-" + tenant[:8],
					change.GitLabTokenHeader:     secret,
					"X-Gitlab-Event":             "Push Hook",
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenant := freshTenant(t, db, "chgreplay")
			id, secret := "wh-"+tc.provider+"-"+tenant[:8], "secret-"+tc.provider+"-"+tenant[:8]
			h := buildChangeHandler(db, map[string]config.ChangeWebhook{id: {TenantID: tenant, Provider: tc.provider, Secret: secret}})
			headers := tc.headers(secret, tenant, tc.body)

			first := postWebhook(t, h, tc.provider, id, tc.body, headers)
			if first.Code != http.StatusAccepted {
				t.Fatalf("first delivery: %d %s", first.Code, first.Body)
			}
			replay := postWebhook(t, h, tc.provider, id, tc.body, headers)
			if replay.Code != http.StatusAccepted {
				t.Fatalf("replay delivery: %d %s", replay.Code, replay.Body)
			}
			if !strings.Contains(replay.Body.String(), `"duplicate":true`) {
				t.Fatalf("replay should be reported as duplicate success: %s", replay.Body)
			}

			if got := countTenantRows(t, db, tenant, `SELECT count(*) FROM change_events WHERE source = $1`, tc.provider); got != 1 {
				t.Fatalf("change event count = %d, want 1", got)
			}
			if got := countTenantRows(t, db, tenant, `SELECT count(*) FROM audit_events WHERE action = 'change.ingest' AND target = $1`, id); got != 1 {
				t.Fatalf("audit ingest count = %d, want 1", got)
			}
			if got := countTenantRows(t, db, tenant, `SELECT COALESCE(sum(duplicate_count), 0)::int FROM webhook_deliveries WHERE credential_id = $1 AND provider = $2`, id, tc.provider); got != 1 {
				t.Fatalf("delivery duplicate count = %d, want 1", got)
			}
		})
	}
}

// An incident surfaces the recent changes that share its target within the window,
// ranked as candidate causes; unrelated changes are not surfaced.
func TestIncidentChangesCorrelation(t *testing.T) {
	db := changeDB(t)
	h := buildChangeHandler(db, nil)
	tenant := freshTenant(t, db, "chgcorr")
	now := time.Now().UTC().Truncate(time.Second)

	seedChange(t, db, tenant, change.Event{Source: "generic", Kind: change.KindDeploy,
		Title: "deploy web to prod", Target: "api.example.com", OccurredAt: now.Add(-5 * time.Minute)})
	seedChange(t, db, tenant, change.Event{Source: "generic", Kind: change.KindDeploy,
		Title: "deploy db", Target: "db.internal", OccurredAt: now.Add(-3 * time.Minute)})

	c := BuildCorrelator(db.Pool(), 5*time.Minute, quietLog())
	inc, err := c.Ingest(context.Background(), incident.Signal{TenantID: tenant, Plane: "network",
		Kind: "alert.firing", Severity: incident.SeverityWarning, Title: "latency to api",
		Target: "api.example.com", OccurredAt: now})
	if err != nil {
		t.Fatal(err)
	}

	rec := apiReq(t, h, http.MethodGet, "/v1/incidents/"+inc.ID+"/changes", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("incident changes: %d %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "deploy web to prod") {
		t.Errorf("the correlated change should be surfaced: %s", body)
	}
	if strings.Contains(body, "deploy db") {
		t.Errorf("an unrelated change must not correlate: %s", body)
	}
}

// The AI RCA cites the likely change: a deploy to the subject becomes evidence the
// answer references.
func TestRCACitesChange(t *testing.T) {
	db := changeDB(t)
	h := buildChangeHandler(db, nil)
	tenant := freshTenant(t, db, "chgrca")
	now := time.Now().UTC()

	seedChange(t, db, tenant, change.Event{Source: "github", Kind: change.KindDeploy,
		Title: "deploy payments-api to prod", Target: "api.example.com", Actor: "alice",
		OccurredAt: now.Add(-10 * time.Minute)})

	rec := apiReq(t, h, http.MethodPost, "/v1/ai/ask", tenant,
		map[string]any{"question": "what changed for api.example.com? any recent deploy?"})
	if rec.Code != http.StatusOK {
		t.Fatalf("ai ask: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "deploy payments-api to prod") {
		t.Errorf("RCA should cite the change as evidence: %s", rec.Body)
	}
}

// AI/RCA evidence must obey both sides of the planned query window. A change that
// occurs after the question's end time is future evidence; it must not be cited
// just because it is newer than the start time.
func TestAIAskExcludesFutureChangeEvidence(t *testing.T) {
	db := changeDB(t)
	h := buildChangeHandler(db, nil)
	tenant := freshTenant(t, db, "chgrcafuture")
	now := time.Now().UTC().Truncate(time.Second)

	seedChange(t, db, tenant, change.Event{Source: "github", Kind: change.KindDeploy,
		Title: "deploy payments-api in current window", Target: "api.example.com", Actor: "alice",
		OccurredAt: now.Add(-10 * time.Minute)})
	seedChange(t, db, tenant, change.Event{Source: "github", Kind: change.KindDeploy,
		Title: "deploy payments-api after query end", Target: "api.example.com", Actor: "mallory",
		OccurredAt: now.Add(2 * time.Hour)})

	rec := apiReq(t, h, http.MethodPost, "/v1/ai/ask", tenant,
		map[string]any{"question": "what changed for api.example.com? any recent deploy?"})
	if rec.Code != http.StatusOK {
		t.Fatalf("ai ask: %d %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if strings.Contains(body, "deploy payments-api after query end") {
		t.Fatalf("RCA cited future change evidence outside the query end: %s", body)
	}
	if !strings.Contains(body, "deploy payments-api in current window") {
		t.Fatalf("RCA should still cite in-window change evidence: %s", body)
	}
}
