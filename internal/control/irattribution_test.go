// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
)

const (
	irTenantA = "00000000-0000-0000-0000-0000000000a1"
	irTenantB = "00000000-0000-0000-0000-0000000000b2"
)

var (
	irRefA = strings.Repeat("a", 64)
	irRefB = strings.Repeat("b", 64)
	irRefC = strings.Repeat("c", 64)
)

type fakeIRInvestigator struct {
	records          map[string]IRAttribution
	revealErr        error
	recordErrOutcome IRAttemptOutcome
	receipts         []IRInvestigationReceipt
	order            []string
	onReceipt        func(IRInvestigationReceipt)
	onRecord         func(context.Context, IRInvestigationReceipt)
	onReveal         func()
}

func (f *fakeIRInvestigator) RecordAttempt(
	ctx context.Context,
	receipt IRInvestigationReceipt,
) error {
	f.receipts = append(f.receipts, receipt)
	f.order = append(f.order, "receipt:"+string(receipt.Outcome))
	if f.onReceipt != nil {
		f.onReceipt(receipt)
	}
	if f.onRecord != nil {
		f.onRecord(ctx, receipt)
	}
	if receipt.Outcome == f.recordErrOutcome {
		return errors.New("provider audit unavailable")
	}
	return nil
}

func (f *fakeIRInvestigator) Reveal(
	_ context.Context,
	tenantID, eventRef string,
) (IRAttribution, error) {
	f.order = append(f.order, "reveal")
	if f.onReveal != nil {
		f.onReveal()
	}
	if f.revealErr != nil {
		return IRAttribution{}, f.revealErr
	}
	record, ok := f.records[tenantID+"\x00"+eventRef]
	if !ok {
		return IRAttribution{}, ErrIRAttributionNotFound
	}
	return record, nil
}

func testIRAttribution(tenantID, eventRef, operator string) IRAttribution {
	return IRAttribution{
		Operator: operator,
		TenantID: tenantID,
		Grant:    "grant-7",
		Surface:  "results.latest",
		Consent:  "tenant-approved:admin@example.test",
		Outcome:  "accessed",
		Reason:   "suspected privileged abuse",
		EventRef: eventRef,
		TS:       time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
	}
}

func testIRPrincipal(tenantID string, mfa, permitted bool) *auth.Principal {
	permissions := map[string]bool{}
	if permitted {
		permissions[permIRInvestigate] = true
	}
	return &auth.Principal{
		TenantID: tenantID, UserID: "investigator-1",
		Email: "investigator@example.test", MFASatisfied: mfa,
		Permissions: permissions, Attributes: map[string]string{"mfa": "true"},
	}
}

func testIRRequest(
	recorder *httptest.ResponseRecorder,
	srv *Server,
	principal *auth.Principal,
	eventRef, body string,
) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/audit/ir/"+eventRef+"/reveal",
		strings.NewReader(body),
	)
	if principal != nil {
		request = request.WithContext(
			auth.WithPrincipal(request.Context(), principal),
		)
	}
	srv.cfg.AuthMode = "session"
	srv.Handler().ServeHTTP(recorder, request)
	return recorder
}

func TestIRRevealSuccessAuditsBeforePlaintext(t *testing.T) {
	fake := &fakeIRInvestigator{records: map[string]IRAttribution{
		irTenantA + "\x00" + irRefA: testIRAttribution(
			irTenantA,
			irRefA,
			"operator-canary@example.test",
		),
	}}
	server := testServer(fakePinger{}).WithIRInvestigator(fake)
	recorder := httptest.NewRecorder()
	fake.onReceipt = func(receipt IRInvestigationReceipt) {
		if receipt.Outcome == IRAttemptSucceeded && recorder.Body.Len() != 0 {
			t.Fatalf(
				"plaintext written before success receipt: %q",
				recorder.Body.String(),
			)
		}
	}
	testIRRequest(
		recorder,
		server,
		testIRPrincipal(irTenantA, true, true),
		irRefA,
		`{"reason":" investigate privileged access "}`,
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("missing no-store response: %v", recorder.Header())
	}
	if !strings.Contains(
		recorder.Body.String(),
		"operator-canary@example.test",
	) {
		t.Fatalf("authorized attribution missing: %s", recorder.Body.String())
	}
	if got, want := strings.Join(
		fake.order,
		",",
	), "receipt:intent,reveal,receipt:succeeded"; got != want {
		t.Fatalf("call order = %q, want %q", got, want)
	}
	if fake.receipts[0].TenantID != irTenantA ||
		fake.receipts[0].Reason != "investigate privileged access" {
		t.Fatalf("intent receipt = %+v", fake.receipts[0])
	}
}

func TestIRRevealClientCancellationCannotEraseResultReceipt(t *testing.T) {
	fake := &fakeIRInvestigator{records: map[string]IRAttribution{
		irTenantA + "\x00" + irRefA: testIRAttribution(
			irTenantA,
			irRefA,
			"operator-canary@example.test",
		),
	}}
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/audit/ir/"+irRefA+"/reveal",
		strings.NewReader(`{"reason":"investigate privileged abuse"}`),
	)
	requestCtx, cancel := context.WithCancel(request.Context())
	request = request.WithContext(auth.WithPrincipal(
		requestCtx,
		testIRPrincipal(irTenantA, true, true),
	))
	fake.onReveal = cancel
	var resultAudited bool
	fake.onRecord = func(
		ctx context.Context,
		receipt IRInvestigationReceipt,
	) {
		if receipt.Outcome != IRAttemptSucceeded {
			return
		}
		if err := ctx.Err(); err != nil {
			t.Fatalf("result receipt inherited client cancellation: %v", err)
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > irRevealResultAuditTimeout {
			t.Fatalf(
				"result receipt deadline = %v, %v; want bounded timeout",
				deadline,
				ok,
			)
		}
		resultAudited = true
	}
	server := testServer(fakePinger{}).WithIRInvestigator(fake)
	server.cfg.AuthMode = "session"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !resultAudited {
		t.Fatalf(
			"canceled reveal status=%d audited=%v body=%s",
			recorder.Code,
			resultAudited,
			recorder.Body.String(),
		)
	}
}

func TestIRRevealSuccessAuditFailureSuppressesPlaintext(t *testing.T) {
	const canary = "must-not-leave-on-audit-failure@example.test"
	fake := &fakeIRInvestigator{
		records: map[string]IRAttribution{
			irTenantA + "\x00" + irRefA: testIRAttribution(
				irTenantA,
				irRefA,
				canary,
			),
		},
		recordErrOutcome: IRAttemptSucceeded,
	}
	recorder := testIRRequest(
		httptest.NewRecorder(),
		testServer(fakePinger{}).WithIRInvestigator(fake),
		testIRPrincipal(irTenantA, true, true),
		irRefA,
		`{"reason":"verify abuse report"}`,
	)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), canary) {
		t.Fatalf("plaintext escaped audit failure: %s", recorder.Body.String())
	}
}

func TestIRRevealTwoTenantIsolationAndMissingAreIndistinguishable(t *testing.T) {
	fake := &fakeIRInvestigator{records: map[string]IRAttribution{
		irTenantA + "\x00" + irRefA: testIRAttribution(
			irTenantA,
			irRefA,
			"operator-a@example.test",
		),
		irTenantB + "\x00" + irRefB: testIRAttribution(
			irTenantB,
			irRefB,
			"operator-b@example.test",
		),
	}}
	server := testServer(fakePinger{}).WithIRInvestigator(fake)
	cross := testIRRequest(
		httptest.NewRecorder(),
		server,
		testIRPrincipal(irTenantA, true, true),
		irRefB,
		`{"reason":"case A"}`,
	)
	missing := testIRRequest(
		httptest.NewRecorder(),
		server,
		testIRPrincipal(irTenantA, true, true),
		irRefC,
		`{"reason":"case A"}`,
	)
	if cross.Code != http.StatusNotFound || missing.Code != http.StatusNotFound {
		t.Fatalf("cross/missing status = %d/%d", cross.Code, missing.Code)
	}
	if testIRErrorContract(t, cross) != testIRErrorContract(t, missing) {
		t.Fatalf(
			"cross-tenant existence oracle: cross=%s missing=%s",
			cross.Body,
			missing.Body,
		)
	}
	if strings.Contains(cross.Body.String(), "operator-b@example.test") {
		t.Fatalf("tenant B attribution leaked: %s", cross.Body.String())
	}
}

func TestIRRevealDedicatedPermissionMFAAndABACDenyBeforeInvestigation(t *testing.T) {
	t.Run("audit read is insufficient", func(t *testing.T) {
		principal := testIRPrincipal(irTenantA, true, false)
		principal.Permissions[permAuditRead] = true
		fake := &fakeIRInvestigator{}
		recorder := testIRRequest(
			httptest.NewRecorder(),
			testServer(fakePinger{}).WithIRInvestigator(fake),
			principal,
			irRefA,
			`{"reason":"must not be parsed before authorization"}`,
		)
		assertIRAuthorizationDenial(t, recorder, fake)
	})
	t.Run("MFA is unconditional", func(t *testing.T) {
		fake := &fakeIRInvestigator{}
		recorder := testIRRequest(
			httptest.NewRecorder(),
			testServer(fakePinger{}).WithIRInvestigator(fake),
			testIRPrincipal(irTenantA, false, true),
			irRefA,
			`{"reason":"must not be parsed before authorization"}`,
		)
		assertIRAuthorizationDenial(t, recorder, fake)
	})
	t.Run("tenant resource ABAC", func(t *testing.T) {
		fake := &fakeIRInvestigator{}
		server := testServer(fakePinger{}).WithIRInvestigator(fake)
		server.abac = &abacCache{
			ttl: time.Minute,
			load: func(context.Context, string) ([]auth.Policy, error) {
				return nil, errors.New("unexpected ABAC cache load")
			},
			data: map[string]abacEntry{
				irTenantA: {
					policies: []auth.Policy{{
						Name: "deny investigators", Effect: auth.PolicyDeny,
						Permission: permIRInvestigate,
						Resource: map[string]string{
							auth.ResourceTenantKey: irTenantA,
						},
						Enabled: true,
					}},
					expiry: time.Now().Add(time.Minute),
				},
			},
			generations: map[string]uint64{},
		}
		principal := testIRPrincipal(irTenantA, true, true)
		denied, err := server.abacDenies(
			context.Background(),
			principal,
			permIRInvestigate,
			map[string]string{auth.ResourceTenantKey: irTenantA},
		)
		if err != nil || !denied {
			t.Fatalf("ABAC fixture denied=%v err=%v", denied, err)
		}
		recorder := testIRRequest(
			httptest.NewRecorder(),
			server,
			principal,
			irRefA,
			`{"reason":"must not be parsed before authorization"}`,
		)
		assertIRAuthorizationDenial(t, recorder, fake)
	})
}

func TestIRRevealRateLimitBoundsRetentionSurvivingReceipts(t *testing.T) {
	fake := &fakeIRInvestigator{}
	server := testServer(fakePinger{}).WithIRInvestigator(fake)
	server.irRevealLimiter = newKeyLimiter(1)
	principal := testIRPrincipal(irTenantA, true, true)
	first := testIRRequest(
		httptest.NewRecorder(),
		server,
		principal,
		irRefA,
		`{"reason":"case A"}`,
	)
	if first.Code != http.StatusNotFound {
		t.Fatalf("first admitted request = %d %s", first.Code, first.Body)
	}
	receipts := len(fake.receipts)
	second := testIRRequest(
		httptest.NewRecorder(),
		server,
		principal,
		irRefA,
		`{"reason":"case A"}`,
	)
	if second.Code != http.StatusTooManyRequests ||
		second.Header().Get("Retry-After") == "" {
		t.Fatalf("rate-limited request = %d headers=%v body=%s",
			second.Code, second.Header(), second.Body)
	}
	if len(fake.receipts) != receipts {
		t.Fatalf("rate limit appended permanent receipts: %d -> %d",
			receipts, len(fake.receipts))
	}
}

func TestIRRevealUnlicensedRouteIsHidden(t *testing.T) {
	recorder := testIRRequest(
		httptest.NewRecorder(),
		testServer(fakePinger{}),
		testIRPrincipal(irTenantA, true, true),
		irRefA,
		`{"reason":"case"}`,
	)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unattached reveal = %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestOrdinaryAuditReadsCannotInvokeIRReveal(t *testing.T) {
	fake := &fakeIRInvestigator{}
	server := testServer(fakePinger{}).WithIRInvestigator(fake)
	principal := testIRPrincipal(irTenantA, true, false)
	principal.Permissions[permAuditRead] = true
	for _, path := range []string{"/v1/audit", "/v1/audit/verify"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request = request.WithContext(
			auth.WithPrincipal(request.Context(), principal),
		)
		server.cfg.AuthMode = "session"
		server.Handler().ServeHTTP(recorder, request)
	}
	if len(fake.order) != 0 {
		t.Fatalf("ordinary audit read touched reveal: %v", fake.order)
	}
}

func TestIRRevealRouteUsesExplicitSensitiveAuditPolicy(t *testing.T) {
	server := testServer(fakePinger{})
	found := false
	for _, route := range server.apiRoutes() {
		if route.Method == http.MethodPost &&
			route.Pattern == irRevealRoutePattern {
			found = true
			if route.Permission != permIRInvestigate {
				t.Fatalf(
					"permission = %q, want %q",
					route.Permission,
					permIRInvestigate,
				)
			}
		}
	}
	if !found {
		t.Fatal("IR reveal route not registered")
	}
	policy, ok := auditPolicyFor(http.MethodPost, irRevealRoutePattern)
	if !ok || policy.Mode != auditModeExplicit ||
		policy.Facet != auditFacetSensitiveRead {
		t.Fatalf("IR reveal policy = %+v found=%v", policy, ok)
	}
}

func assertIRAuthorizationDenial(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	fake *fakeIRInvestigator,
) {
	t.Helper()
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(fake.receipts) != 0 ||
		strings.Contains(strings.Join(fake.order, ","), "reveal") {
		t.Fatalf("authorization denial crossed reveal boundary: %+v", fake)
	}
}

func testIRErrorContract(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
) string {
	t.Helper()
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error response: %v body=%s", err, recorder.Body.String())
	}
	return body.Error.Code + "\x00" + body.Error.Message
}
