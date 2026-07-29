// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package provider

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/ee/silo"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

type failingPGAudit struct{}

func (failingPGAudit) Append(context.Context, string, string, string, map[string]any) error {
	return errAuditUnavailable
}

func (failingPGAudit) AppendTx(
	ctx context.Context,
	q tenancy.Querier,
	actor, action, target string,
	_ map[string]any,
) error {
	// Exercise the real transaction-bound audit implementation, but force a
	// deterministic serialization failure before its insert.
	_, err := audit.ProviderAppendTx(ctx, q, actor, action, target, map[string]any{
		"unencodable": make(chan struct{}),
	})
	if err == nil {
		return errors.New("provider audit failure injection unexpectedly succeeded")
	}
	return fmt.Errorf("%w: %v", errAuditUnavailable, err)
}

// The PG-backed provider store against the real test stack (Kafka-less: only
// Postgres is needed). Proves: the 0024 schema works end-to-end, the
// probectl_provider role can run the whole lifecycle, and — the storage-layer
// guardrail — that role CANNOT read telemetry tables at all.
func pgPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.PostgresDSN()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

type pgBreakGlassRaceFixture struct {
	pool      *pgxpool.Pool
	store     *PGStore
	pausing   *pauseFirstMutationStore
	service   *Service
	telemetry *countingTelemetry
	operator  Operator
	grant     Grant
	now       *time.Time
}

func newPGBreakGlassRaceFixture(t *testing.T) *pgBreakGlassRaceFixture {
	t.Helper()
	pool := pgPool(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	store := NewPGStore(pool)
	pausing := newPauseFirstMutationStore(store)
	t.Cleanup(func() {
		select {
		case <-pausing.resume:
		default:
			close(pausing.resume)
		}
	})
	telemetry := &countingTelemetry{}
	now := time.Now().UTC()
	stamp := now.UnixNano()

	operator, err := store.CreateOperator(ctx, Operator{
		Email: fmt.Sprintf("breakglass-race-%d@msp.example", stamp),
		Name:  "Break-glass Race Operator",
		Role:  RoleOperator,
	}, crypto.Hash([]byte(fmt.Sprintf("race-enrollment-%d", stamp))))
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := store.CreateTenant(
		ctx,
		fmt.Sprintf("breakglass-race-%d", stamp),
		"Break-glass Race Tenant",
		"pooled",
		"",
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := store.CreateGrant(ctx, Grant{
		OperatorID: operator.ID,
		TenantID:   tenant.ID,
		Reason:     "real PostgreSQL authorization-race regression",
		Scope:      "read",
		GrantedBy:  operator.Email,
		GrantedAt:  now.Add(-time.Minute),
		ExpiresAt:  now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsentGrant(ctx, grant.ID, "tenant-admin@example.test", now.Add(-30*time.Second)); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(
		pausing,
		&providerAudit{pool: pool},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		telemetry,
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.WithClock(func() time.Time { return now })

	return &pgBreakGlassRaceFixture{
		pool:      pool,
		store:     store,
		pausing:   pausing,
		service:   service,
		telemetry: telemetry,
		operator:  operator,
		grant:     grant,
		now:       &now,
	}
}

func (f *pgBreakGlassRaceFixture) startAccess() <-chan breakGlassRaceResult {
	out := make(chan breakGlassRaceResult, 1)
	go func() {
		data, err := f.service.BreakGlassResults(context.Background(), f.operator, f.grant.ID)
		out <- breakGlassRaceResult{data: data, err: err}
	}()
	return out
}

func (f *pgBreakGlassRaceFixture) assertDeniedWithoutUse(t *testing.T, result breakGlassRaceResult) {
	t.Helper()
	if !errors.Is(result.err, ErrNotConsented) {
		t.Fatalf("BreakGlassResults error = %v, want %v", result.err, ErrNotConsented)
	}
	if result.data != nil {
		t.Fatalf("BreakGlassResults data = %#v, want nil", result.data)
	}
	if f.telemetry.calls != 0 {
		t.Fatalf("telemetry reads = %d, want 0", f.telemetry.calls)
	}
	stored, err := f.store.GetGrant(context.Background(), f.grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.UseCount != 0 {
		t.Fatalf("grant use_count = %d, want 0", stored.UseCount)
	}
	var accessAudits int
	if err := tenancy.InProvider(context.Background(), f.pool, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2`,
			"provider.breakglass_access", f.grant.ID,
		).Scan(&accessAudits)
	}); err != nil {
		t.Fatal(err)
	}
	if accessAudits != 0 {
		t.Fatalf("break-glass access audits = %d, want 0", accessAudits)
	}
}

func TestPGBreakGlassAccessLosesRevokeRace(t *testing.T) {
	f := newPGBreakGlassRaceFixture(t)
	result := f.startAccess()
	awaitBreakGlassRaceSignal(t, f.pausing.entered)

	if _, err := f.service.Revoke(context.Background(), "incident-commander@msp.example", f.grant.ID); err != nil {
		t.Fatal(err)
	}
	close(f.pausing.resume)

	f.assertDeniedWithoutUse(t, awaitBreakGlassRaceResult(t, result))
}

func TestPGBreakGlassAccessLosesExpiryRace(t *testing.T) {
	f := newPGBreakGlassRaceFixture(t)
	result := f.startAccess()
	awaitBreakGlassRaceSignal(t, f.pausing.entered)

	*f.now = f.grant.ExpiresAt
	close(f.pausing.resume)

	f.assertDeniedWithoutUse(t, awaitBreakGlassRaceResult(t, result))
}

func TestPGSiloProvisionFailureIsNonRoutableAndResumable(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	ctx := context.Background()
	store := NewPGStore(pool)
	router := silo.NewRouter(pool, nil, time.Hour)
	siloOps := &fakeSilo{}
	service, err := NewService(
		store,
		&providerAudit{pool: pool},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		fakeTelemetry{},
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.WithSilo(siloOps, router.Invalidate)
	stamp := time.Now().UTC().UnixNano()

	published, err := service.Provision(
		ctx,
		"operator@msp.example",
		fmt.Sprintf("pg-published-%d", stamp),
		"Published Control",
		"siloed",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	siloOps.mu.Lock()
	siloOps.failNext = true
	siloOps.mu.Unlock()
	pendingSlug := fmt.Sprintf("pg-pending-%d", stamp)
	if _, err := service.Provision(
		ctx,
		"operator@msp.example",
		pendingSlug,
		"Pending Control",
		"siloed",
		"",
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first pending provision error = %v, want deadline exceeded", err)
	}
	pending, err := store.TenantBySlug(ctx, pendingSlug)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Status != "provisioning" {
		t.Fatalf("pending status = %q, want provisioning", pending.Status)
	}

	if targets, err := router.TargetsFor(ctx, published.ID); err != nil {
		t.Fatalf("published tenant routing: %v", err)
	} else if targets.Model != tenancy.IsolationSiloed {
		t.Fatalf("published tenant targets = %+v", targets)
	}
	if _, err := router.TargetsFor(ctx, pending.ID); !errors.Is(err, silo.ErrUnknownTenant) {
		t.Fatalf("pending tenant routing error = %v, want ErrUnknownTenant", err)
	}
	fleet, err := store.FleetSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fleetIDs := map[string]bool{}
	for _, tenant := range fleet {
		fleetIDs[tenant.TenantID] = true
	}
	if !fleetIDs[published.ID] || fleetIDs[pending.ID] {
		t.Fatalf("fleet publication published=%v pending=%v, want true/false", fleetIDs[published.ID], fleetIDs[pending.ID])
	}
	var registryRows, stagingRows int
	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		if err := q.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id = $1`, pending.ID).Scan(&registryRows); err != nil {
			return err
		}
		return q.QueryRow(ctx,
			`SELECT count(*) FROM tenant_provisioning WHERE id = $1`, pending.ID).Scan(&stagingRows)
	}); err != nil {
		t.Fatal(err)
	}
	if registryRows != 0 || stagingRows != 1 {
		t.Fatalf("pending publication registry=%d staging=%d, want 0/1", registryRows, stagingRows)
	}

	completed, err := service.Provision(
		ctx,
		"operator@msp.example",
		pendingSlug,
		"Pending Control",
		"siloed",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if completed.ID != pending.ID || completed.Status != "active" {
		t.Fatalf("completed tenant = %+v, want same id %q active", completed, pending.ID)
	}
	if targets, err := router.TargetsFor(ctx, pending.ID); err != nil {
		t.Fatalf("completed tenant routing: %v", err)
	} else if targets.Model != tenancy.IsolationSiloed {
		t.Fatalf("completed tenant targets = %+v", targets)
	}
	fleet, err = store.FleetSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fleetIDs = map[string]bool{}
	for _, tenant := range fleet {
		fleetIDs[tenant.TenantID] = true
	}
	if !fleetIDs[published.ID] || !fleetIDs[pending.ID] {
		t.Fatalf("completed fleet publication published=%v resumed=%v, want true/true", fleetIDs[published.ID], fleetIDs[pending.ID])
	}

	registryRows, stagingRows = 0, 0
	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		if err := q.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id = $1`, pending.ID).Scan(&registryRows); err != nil {
			return err
		}
		return q.QueryRow(ctx,
			`SELECT count(*) FROM tenant_provisioning WHERE id = $1`, pending.ID).Scan(&stagingRows)
	}); err != nil {
		t.Fatal(err)
	}
	if registryRows != 1 || stagingRows != 0 {
		t.Fatalf("completed publication registry=%d staging=%d, want 1/0", registryRows, stagingRows)
	}
}

func TestPGSiloConcurrentCompletionHonorsTenantBand(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	ctx := context.Background()
	store := NewPGStore(pool)
	baseline, err := store.CountActiveTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	barrier := newBarrierSilo()
	service, err := NewService(
		store,
		&providerAudit{pool: pool},
		licenseManager(t, license.TierMSP, baseline+1, 90*24*time.Hour),
		fakeTelemetry{},
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	service.WithSilo(barrier, nil)
	stamp := time.Now().UTC().UnixNano()
	slugs := []string{
		fmt.Sprintf("pg-band-a-%d", stamp),
		fmt.Sprintf("pg-band-b-%d", stamp),
	}

	type result struct {
		tenant Tenant
		err    error
	}
	results := make(chan result, 2)
	for _, slug := range slugs {
		go func(slug string) {
			tenant, err := service.Provision(ctx, "operator@msp.example", slug, slug, "siloed", "")
			results <- result{tenant: tenant, err: err}
		}(slug)
	}
	for range 2 {
		select {
		case <-barrier.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for PostgreSQL band-race provisioning")
		}
	}
	close(barrier.release)

	successes, bandFailures := 0, 0
	for range 2 {
		select {
		case got := <-results:
			switch {
			case got.err == nil:
				successes++
			case errors.Is(got.err, ErrBandExhausted):
				bandFailures++
			default:
				t.Fatalf("PostgreSQL concurrent provision error = %v", got.err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for PostgreSQL band-race results")
		}
	}
	if successes != 1 || bandFailures != 1 {
		t.Fatalf("PostgreSQL concurrent results success=%d band_exhausted=%d, want 1/1", successes, bandFailures)
	}
	active, err := store.CountActiveTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if active != baseline+1 {
		t.Fatalf("active tenant count = %d, want baseline+1 (%d)", active, baseline+1)
	}
	statuses := map[string]int{}
	for _, slug := range slugs {
		tenant, err := store.TenantBySlug(ctx, slug)
		if err != nil {
			t.Fatal(err)
		}
		statuses[tenant.Status]++
	}
	if statuses["active"] != 1 || statuses["provisioning"] != 1 {
		t.Fatalf("PostgreSQL publication states = %v, want active=1 provisioning=1", statuses)
	}
}

func TestPGProviderMutationAndAuditAreAtomic(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	ctx := context.Background()
	store := NewPGStore(pool)
	stamp := time.Now().UTC().UnixNano()

	target, err := store.CreateTenant(
		ctx,
		fmt.Sprintf("audit-target-%d", stamp),
		"Target Before",
		"pooled",
		"",
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	bystander, err := store.CreateTenant(
		ctx,
		fmt.Sprintf("audit-bystander-%d", stamp),
		"Bystander Before",
		"pooled",
		"",
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	svc, err := NewService(
		store,
		failingPGAudit{},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		fakeTelemetry{},
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Configure(ctx, "admin@msp.example", target.ID, "Target Changed"); !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("Configure error = %v, want %v", err, errAuditUnavailable)
	}

	tenants, err := store.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]string, len(tenants))
	for _, tenant := range tenants {
		names[tenant.ID] = tenant.Name
	}
	if got := names[target.ID]; got != "Target Before" {
		t.Fatalf("target name after failed audit = %q, want %q", got, "Target Before")
	}
	if got := names[bystander.ID]; got != "Bystander Before" {
		t.Fatalf("bystander name after target rollback = %q, want %q", got, "Bystander Before")
	}

	var auditRows int
	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2`,
			"provider.tenant_configure", target.ID,
		).Scan(&auditRows)
	}); err != nil {
		t.Fatal(err)
	}
	if auditRows != 0 {
		t.Fatalf("audit rows for rolled-back mutation = %d, want 0", auditRows)
	}

	productionService, err := NewService(
		store,
		&providerAudit{pool: pool},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		fakeTelemetry{},
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := productionService.Configure(ctx, "admin@msp.example", target.ID, "Target After"); err != nil {
		t.Fatalf("production Configure: %v", err)
	}

	tenants, err = store.ListTenants(ctx)
	if err != nil {
		t.Fatal(err)
	}
	names = make(map[string]string, len(tenants))
	for _, tenant := range tenants {
		names[tenant.ID] = tenant.Name
	}
	if got := names[target.ID]; got != "Target After" {
		t.Fatalf("target name after successful audited mutation = %q, want %q", got, "Target After")
	}
	if got := names[bystander.ID]; got != "Bystander Before" {
		t.Fatalf("bystander name after successful target mutation = %q, want %q", got, "Bystander Before")
	}
	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2`,
			"provider.tenant_configure", target.ID,
		).Scan(&auditRows)
	}); err != nil {
		t.Fatal(err)
	}
	if auditRows != 1 {
		t.Fatalf("audit rows for committed mutation = %d, want 1", auditRows)
	}
}

func TestPGEnrollStartTOTPAndAuditAreAtomic(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	ctx := context.Background()
	store := NewPGStore(pool)
	stamp := time.Now().UTC().UnixNano()
	enrollToken := fmt.Sprintf("audit-atomic-enrollment-token-%d", stamp)
	op, err := store.CreateOperator(ctx, Operator{
		Email: fmt.Sprintf("enroll-audit-%d@msp.example", stamp),
		Name:  "Enroll Audit",
		Role:  RoleOperator,
	}, crypto.Hash([]byte(enrollToken)))
	if err != nil {
		t.Fatal(err)
	}

	failingService, err := NewService(
		store,
		failingPGAudit{},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		fakeTelemetry{},
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := failingService.EnrollStart(ctx, enrollToken); !errors.Is(err, errAuditUnavailable) {
		t.Fatalf("EnrollStart error = %v, want %v", err, errAuditUnavailable)
	}
	_, cred, err := store.OperatorByEmail(ctx, op.Email)
	if err != nil {
		t.Fatal(err)
	}
	if cred.TOTP.KeyID != "" || len(cred.TOTP.WrappedDEK) != 0 || len(cred.TOTP.Ciphertext) != 0 {
		t.Fatalf("TOTP credential survived failed audit: %+v", cred.TOTP)
	}

	const action = "provider.operator_totp_bound"
	var auditRows int
	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2`,
			action, op.ID,
		).Scan(&auditRows)
	}); err != nil {
		t.Fatal(err)
	}
	if auditRows != 0 {
		t.Fatalf("audit rows for rolled-back TOTP mutation = %d, want 0", auditRows)
	}

	productionService, err := NewService(
		store,
		&providerAudit{pool: pool},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		fakeTelemetry{},
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, secret, _, err := productionService.EnrollStart(ctx, enrollToken); err != nil {
		t.Fatalf("production EnrollStart: %v", err)
	} else if secret == "" {
		t.Fatal("production EnrollStart returned an empty TOTP secret")
	}
	_, cred, err = store.OperatorByEmail(ctx, op.Email)
	if err != nil {
		t.Fatal(err)
	}
	if cred.TOTP.KeyID == "" || len(cred.TOTP.WrappedDEK) == 0 || len(cred.TOTP.Ciphertext) == 0 {
		t.Fatalf("committed TOTP credential is incomplete: %+v", cred.TOTP)
	}
	if err := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2`,
			action, op.ID,
		).Scan(&auditRows)
	}); err != nil {
		t.Fatal(err)
	}
	if auditRows != 1 {
		t.Fatalf("audit rows for committed TOTP mutation = %d, want 1", auditRows)
	}
}

func TestPGStoreLifecycle(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	st := NewPGStore(pool)
	ctx := context.Background()

	// Operator round-trip incl. sealed TOTP columns.
	tok := crypto.Hash([]byte("enroll-integration"))
	op, err := st.CreateOperator(ctx, Operator{Email: "it@msp.example", Name: "IT", Role: RoleAdmin}, tok)
	if err != nil && err != ErrConflict {
		t.Fatalf("create operator: %v", err)
	}
	if err == ErrConflict { // idempotent re-runs
		o, _, e := st.OperatorByEmail(ctx, "it@msp.example")
		if e != nil {
			t.Fatal(e)
		}
		op = *o
	}
	if _, err := st.OperatorByEnrollHash(ctx, tok); err != nil && !op.Enrolled {
		t.Fatalf("enroll hash lookup: %v", err)
	}
	sealed := crypto.Sealed{KeyID: "it", WrappedDEK: []byte{1, 2}, Ciphertext: []byte{3, 4}}
	if err := st.SetOperatorTOTP(ctx, op.ID, sealed); err != nil {
		t.Fatal(err)
	}
	if err := st.ActivateOperator(ctx, op.ID, "pbkdf2$sha256$600000$x$y"); err != nil {
		t.Fatal(err)
	}
	got, cred, err := st.OperatorByEmail(ctx, "it@msp.example")
	if err != nil || !got.Enrolled || cred.TOTP.KeyID != "it" {
		t.Fatalf("operator readback: %+v %+v %v", got, cred, err)
	}

	// Tenant lifecycle.
	slug := "it-" + time.Now().UTC().Format("150405")
	tn, err := st.CreateTenant(ctx, slug, "Integration Tenant", "pooled", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetTenantStatus(ctx, tn.ID, "suspended"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetTenantStatus(ctx, tn.ID, "offboarding"); err != nil {
		t.Fatal(err)
	}

	// Grants.
	g, err := st.CreateGrant(ctx, Grant{
		OperatorID: op.ID, TenantID: tn.ID, Reason: "integration", Scope: "read",
		GrantedBy: op.Email, GrantedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ConsentGrant(ctx, g.ID, "admin@tenant", time.Now()); err != nil {
		t.Fatal(err)
	}
	used, err := st.UseGrant(ctx, g.ID, op.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if used.UseCount != 1 {
		t.Fatalf("used grant count = %d, want 1", used.UseCount)
	}
	back, err := st.GetGrant(ctx, g.ID)
	if err != nil || back.UseCount != 1 || back.ConsentedAt == nil {
		t.Fatalf("grant readback: %+v %v", back, err)
	}

	// Fleet aggregation runs (rows depend on the shared DB's agents).
	if _, err := st.FleetSummary(ctx); err != nil {
		t.Fatalf("fleet: %v", err)
	}
}

// TestProviderRoleCannotReadTelemetry is the storage-layer guardrail test:
// the probectl_provider role has NO grant on results/tests — a direct read
// attempt fails with a permission error, no matter what the Go code does.
func TestProviderRoleCannotReadTelemetry(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	err := tenancy.InProvider(context.Background(), pool, func(ctx context.Context, q tenancy.Querier) error {
		var n int
		return q.QueryRow(ctx, `SELECT count(*) FROM results`).Scan(&n)
	})
	if err == nil {
		t.Fatal("probectl_provider must NOT be able to read the results table")
	}
	err = tenancy.InProvider(context.Background(), pool, func(ctx context.Context, q tenancy.Querier) error {
		var n int
		return q.QueryRow(ctx, `SELECT count(*) FROM tests`).Scan(&n)
	})
	if err == nil {
		t.Fatal("probectl_provider must NOT be able to read the tests table")
	}
	// And the sanctioned read DOES work: agents via the explicit fleet policy.
	err = tenancy.InProvider(context.Background(), pool, func(ctx context.Context, q tenancy.Querier) error {
		var n int
		return q.QueryRow(ctx, `SELECT count(*) FROM agents`).Scan(&n)
	})
	if err != nil {
		t.Fatalf("the fleet policy read must work: %v", err)
	}
}

type integrationPermissionLoader struct{}

func (integrationPermissionLoader) ForUser(context.Context, string, string) ([]string, error) {
	return []string{consentPermission}, nil
}

// TestCoreTenantAuthAuthorizationContextIsTenantScoped exercises the production
// consent adapter against real FORCE-RLS stores. Tenant A's subject and deny
// policy must be returned only for tenant A; tenant B remains authorized, and a
// tenant-A session cannot load tenant B's user by ID.
func TestCoreTenantAuthAuthorizationContextIsTenantScoped(t *testing.T) {
	pool := pgPool(t)
	defer pool.Close()
	ctx := context.Background()
	st := NewPGStore(pool)
	stamp := time.Now().UTC().UnixNano()

	tenantA, err := st.CreateTenant(ctx, fmt.Sprintf("bg-abac-a-%d", stamp), "Break-glass ABAC A", "pooled", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := st.CreateTenant(ctx, fmt.Sprintf("bg-abac-b-%d", stamp), "Break-glass ABAC B", "pooled", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	seed := func(t *testing.T, tenantID, department, policyName string) *store.User {
		t.Helper()
		var user *store.User
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			user, err = (store.Users{}).CreateSCIM(ctx, sc, store.User{
				Email:      fmt.Sprintf("%s-%d@example.test", department, stamp),
				UserName:   fmt.Sprintf("%s-%d", department, stamp),
				Attributes: map[string]string{"department": department},
			})
			if err != nil {
				return err
			}
			_, err = (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{
				Name:       policyName,
				Effect:     auth.PolicyDeny,
				Permission: consentPermission,
				Subject:    map[string]string{"department": "contractor"},
				Priority:   100,
				Enabled:    true,
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return user
	}

	userA := seed(t, tenantA.ID, "contractor", "tenant-a-contractor-deny")
	userB := seed(t, tenantB.ID, "employee", "tenant-b-contractor-deny")
	adapter := coreTenantAuth{perms: integrationPermissionLoader{}, pool: pool}

	principalA, policiesA, err := adapter.AuthorizationContext(ctx, &auth.Session{
		TenantID: tenantA.ID, UserID: userA.ID, Email: userA.Email, MFASatisfied: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if principalA.TenantID != tenantA.ID || principalA.Attributes["department"] != "contractor" ||
		len(policiesA) != 1 || policiesA[0].Name != "tenant-a-contractor-deny" {
		t.Fatalf("tenant A authorization context crossed scope: principal=%+v policies=%+v", principalA, policiesA)
	}
	if auth.Authorize(principalA, consentPermission, policiesA,
		map[string]string{auth.ResourceTenantKey: tenantA.ID}) {
		t.Fatal("tenant A contractor deny policy did not override directory.write")
	}

	principalB, policiesB, err := adapter.AuthorizationContext(ctx, &auth.Session{
		TenantID: tenantB.ID, UserID: userB.ID, Email: userB.Email, MFASatisfied: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if principalB.TenantID != tenantB.ID || principalB.Attributes["department"] != "employee" ||
		len(policiesB) != 1 || policiesB[0].Name != "tenant-b-contractor-deny" {
		t.Fatalf("tenant B authorization context crossed scope: principal=%+v policies=%+v", principalB, policiesB)
	}
	if !auth.Authorize(principalB, consentPermission, policiesB,
		map[string]string{auth.ResourceTenantKey: tenantB.ID}) {
		t.Fatal("tenant A's matching subject/policy state affected tenant B")
	}

	if _, _, err := adapter.AuthorizationContext(ctx, &auth.Session{
		TenantID: tenantA.ID, UserID: userB.ID, Email: userB.Email,
	}); err == nil {
		t.Fatal("tenant A scope loaded tenant B's subject by ID")
	}
}
