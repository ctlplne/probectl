// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration || isolation

package audit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/store"
)

func TestIRCryptoShredCoverageIsolationAndRecoveryDenial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	pool := isolatedIRWORMDatabase(t)

	tenantA, err := store.NewTenants(pool).Create(
		ctx,
		"ir-shred-a",
		"IR Shred A",
	)
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := store.NewTenants(pool).Create(
		ctx,
		"ir-shred-b",
		"IR Shred B",
	)
	if err != nil {
		t.Fatal(err)
	}
	tenantWithoutKey, err := store.NewTenants(pool).Create(
		ctx,
		"ir-shred-empty",
		"IR Shred Empty",
	)
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	publicDirectory := filepath.Join(root, "public")
	privateDirectory := filepath.Join(root, "private")
	if err := os.Mkdir(publicDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(privateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	unlock, err := crypto.NewStaticKeyProvider(
		"test-ir-artifact-unlock",
		bytes.Repeat([]byte{0x5a}, crypto.KeySize),
	)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := make(map[string]irCryptoShredTestArtifacts, 2)
	for _, tenantID := range []string{tenantA.ID, tenantB.ID} {
		artifacts[tenantID] = writeIRCryptoShredTestArtifacts(
			t,
			ctx,
			unlock,
			publicDirectory,
			privateDirectory,
			tenantID,
		)
	}

	publicKeys, err := NewLocalIRPublicKeyResolver(publicDirectory)
	if err != nil {
		t.Fatal(err)
	}
	privateKeys, err := NewLocalIRPrivateKeyResolver(
		privateDirectory,
		unlock,
	)
	if err != nil {
		t.Fatal(err)
	}
	destroyer, err := NewLocalIRKeyArtifactDestroyer(
		publicDirectory,
		privateDirectory,
	)
	if err != nil {
		t.Fatal(err)
	}
	signingPrivate, signingPublic, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	sidecar, err := NewIRStagePG(
		pool,
		publicKeys,
		signingPrivate,
		signingPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	objects := objectstore.NewMemory()
	worm, err := NewWormExporterPG(
		pool,
		objects,
		signingPrivate,
		signingPublic,
		testLog(),
	)
	if err != nil {
		t.Fatal(err)
	}
	worm.WithIRWORMDurability(sidecar)
	revealer, err := NewIRRevealer(worm, sidecar, privateKeys)
	if err != nil {
		t.Fatal(err)
	}
	countingDestroyer := &countingIRKeyArtifactDestroyer{
		delegate: destroyer,
	}
	lifecycle, err := NewIRKeyLifecycle(worm, sidecar, countingDestroyer)
	if err != nil {
		t.Fatal(err)
	}

	events := make(map[string]Event, 2)
	attributions := make(map[string]IRAttribution, 2)
	for _, tenantID := range []string{tenantA.ID, tenantB.ID} {
		attribution := IRAttribution{
			Operator: "operator-" + tenantID[:8],
			TenantID: tenantID,
			Grant:    "grant-" + tenantID[:8],
			Surface:  "results.latest",
			Consent:  "tenant-approved:" + tenantID[:8],
			Outcome:  "accessed",
			Reason:   "reconstruct privileged incident access",
		}
		event, err := ProviderAppendBreakGlass(
			ctx,
			pool,
			sidecar,
			attribution.Operator,
			"provider.breakglass_access",
			attribution.Grant,
			map[string]any{
				"tenant":  tenantID,
				"surface": attribution.Surface,
				"reason":  attribution.Reason,
			},
			attribution,
		)
		if err != nil {
			t.Fatalf("append tenant %s protected event: %v", tenantID, err)
		}
		events[tenantID] = event
		attributions[tenantID] = attribution
	}

	// Fail-before direction: no key or tenant store is touched until every
	// sidecar record is covered by a verified signed WORM segment.
	if planID, err := lifecycle.Plan(
		ctx,
		tenantA.ID,
		"deletion-operator",
	); err == nil || planID != "" {
		t.Fatalf("uncovered IR plan = (%q, %v), want fail closed", planID, err)
	}
	assertIRCryptoShredLedgerCount(t, pool, tenantA.ID, 0)
	assertIRCryptoShredArtifactsPresent(t, artifacts[tenantA.ID])

	exported, err := worm.ExportOnce(ctx)
	if err != nil {
		t.Fatalf("export signed WORM coverage: %v", err)
	}
	if exported != 3 {
		t.Fatalf("exported provider events = %d, want 3", exported)
	}
	if err := worm.ReconcileIRWORMDurability(ctx); err != nil {
		t.Fatalf("reconcile IR WORM coverage: %v", err)
	}
	for _, tenantID := range []string{tenantA.ID, tenantB.ID} {
		revealed, err := revealer.Reveal(
			ctx,
			tenantID,
			events[tenantID].Hash,
		)
		if err != nil {
			t.Fatalf("pre-shred reveal tenant %s: %v", tenantID, err)
		}
		assertIntegrationIRAttribution(
			t,
			revealed,
			attributions[tenantID],
		)
	}

	// The reveal holds the tenant advisory lock through the final Open. A
	// concurrent plan cannot slip between the active-ledger check and key use.
	revealEntered := make(chan struct{})
	releaseReveal := make(chan struct{})
	blockingRevealer, err := NewIRRevealer(
		worm,
		sidecar,
		&blockingIROpenResolver{
			delegate: privateKeys,
			entered:  revealEntered,
			release:  releaseReveal,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	revealDone := make(chan error, 1)
	go func() {
		_, err := blockingRevealer.Reveal(
			ctx,
			tenantA.ID,
			events[tenantA.ID].Hash,
		)
		revealDone <- err
	}()
	select {
	case <-revealEntered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	type planResult struct {
		id  string
		err error
	}
	planDone := make(chan planResult, 1)
	go func() {
		id, err := lifecycle.Plan(
			ctx,
			tenantA.ID,
			"deletion-operator",
		)
		planDone <- planResult{id: id, err: err}
	}()
	select {
	case result := <-planDone:
		t.Fatalf(
			"IR plan bypassed an in-flight reveal lock: id=%q err=%v",
			result.id,
			result.err,
		)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseReveal)
	if err := <-revealDone; err != nil {
		t.Fatalf("in-flight reveal before plan: %v", err)
	}
	result := <-planDone
	if result.err != nil {
		t.Fatalf("plan covered tenant-A IR destruction: %v", result.err)
	}
	planID := result.id
	if !irLowerHex64.MatchString(planID) {
		t.Fatalf("plan id = %q, want signed digest", planID)
	}
	if _, err := revealer.Reveal(
		ctx,
		tenantA.ID,
		events[tenantA.ID].Hash,
	); !errors.Is(err, ErrIRKeyUnavailable) {
		t.Fatalf("planned tenant-A reveal = %v, want key unavailable", err)
	}
	frozenTarget := "grant-after-plan"
	if _, err := ProviderAppendBreakGlass(
		ctx,
		pool,
		sidecar,
		"operator-a",
		"provider.breakglass_access",
		frozenTarget,
		map[string]any{
			"tenant": tenantA.ID, "surface": "results.latest",
			"reason": "must be frozen",
		},
		IRAttribution{
			Operator: "operator-a", TenantID: tenantA.ID,
			Grant: frozenTarget, Surface: "results.latest",
			Consent: "tenant-approved:test", Outcome: "accessed",
			Reason: "must be frozen",
		},
	); !errors.Is(err, ErrIRKeyUnavailable) {
		t.Fatalf("tenant-A append after plan = %v, want key unavailable", err)
	}

	// Tenant B remains live at both the key and storage layer.
	bTarget := "grant-b-after-a-plan"
	if _, err := ProviderAppendBreakGlass(
		ctx,
		pool,
		sidecar,
		"operator-b",
		"provider.breakglass_access",
		bTarget,
		map[string]any{
			"tenant": tenantB.ID, "surface": "results.latest",
			"reason": "prove tenant B remains writable",
		},
		IRAttribution{
			Operator: "operator-b", TenantID: tenantB.ID,
			Grant: bTarget, Surface: "results.latest",
			Consent: "tenant-approved:test", Outcome: "accessed",
			Reason: "prove tenant B remains writable",
		},
	); err != nil {
		t.Fatalf("tenant-B append after tenant-A plan: %v", err)
	}
	if revealed, err := revealer.Reveal(
		ctx,
		tenantB.ID,
		events[tenantB.ID].Hash,
	); err != nil {
		t.Fatalf("tenant-B reveal after tenant-A plan: %v", err)
	} else {
		assertIntegrationIRAttribution(t, revealed, attributions[tenantB.ID])
	}

	var originalHeadHash string
	if err := pool.QueryRow(
		ctx,
		`SELECT last_hash
		   FROM public.ir_attribution_heads
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	).Scan(&originalHeadHash); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_attribution_heads
		    SET last_hash = repeat('0', 64)
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Execute(
		ctx,
		tenantA.ID,
		"deletion-operator",
		planID,
	); err == nil {
		t.Fatal("execute accepted a sidecar head changed after its signed plan")
	}
	if countingDestroyer.destroyCalls != 0 {
		t.Fatalf(
			"destroy calls after post-plan sidecar tamper = %d, want 0",
			countingDestroyer.destroyCalls,
		)
	}
	assertIRCryptoShredArtifactsPresent(t, artifacts[tenantA.ID])
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_attribution_heads
		    SET last_hash = $2
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
		originalHeadHash,
	); err != nil {
		t.Fatal(err)
	}

	if err := lifecycle.Execute(
		ctx,
		tenantA.ID,
		"deletion-operator",
		planID,
	); err != nil {
		t.Fatalf("execute tenant-A IR crypto-shred: %v", err)
	}
	// Completion retry is idempotent and cannot touch tenant B.
	if err := lifecycle.Execute(
		ctx,
		tenantA.ID,
		"deletion-operator",
		planID,
	); err != nil {
		t.Fatalf("retry tenant-A IR crypto-shred: %v", err)
	}
	if countingDestroyer.destroyCalls != 1 {
		t.Fatalf(
			"destroy calls after completion retry = %d, want 1",
			countingDestroyer.destroyCalls,
		)
	}
	assertIRCryptoShredArtifactsAbsent(t, artifacts[tenantA.ID])
	assertIRCryptoShredArtifactsPresent(t, artifacts[tenantB.ID])
	assertIRCryptoShredLedgerCount(t, pool, tenantA.ID, 2)
	assertIRCryptoShredProviderIsolation(
		t,
		pool,
		tenantA.ID,
		tenantB.ID,
	)
	if err := lifecycle.VerifyIRKeyShredLedger(ctx); err != nil {
		t.Fatalf("verify signed key-shred ledger: %v", err)
	}

	const postShredOperator = "post-shred-operator-canary@example.test"
	var postShredEventsBefore int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM public.provider_audit_events WHERE action = $1`,
		ActionIRPostShredRevealDenied,
	).Scan(&postShredEventsBefore); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.RecordIRPostShredRevealAttempt(
		ctx,
		tenantB.ID,
		postShredOperator,
	); err == nil {
		t.Fatal("post-shred receipt accepted a tenant without a signed shred tombstone")
	}
	var postShredEventsAfterUnshredded int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM public.provider_audit_events WHERE action = $1`,
		ActionIRPostShredRevealDenied,
	).Scan(&postShredEventsAfterUnshredded); err != nil {
		t.Fatal(err)
	}
	if postShredEventsAfterUnshredded != postShredEventsBefore {
		t.Fatal("failed post-shred precondition left an unaudited provider event")
	}

	// The provider event and signed tombstone are one transaction. Force the
	// companion insert to fail and prove that no event can commit alone.
	if _, err := pool.Exec(
		ctx,
		`REVOKE INSERT ON public.ir_post_shred_attempt_records
		 FROM probectl_provider`,
	); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`GRANT SELECT, INSERT ON public.ir_post_shred_attempt_records
			 TO probectl_provider`,
		)
	})
	if err := sidecar.RecordIRPostShredRevealAttempt(
		ctx,
		tenantA.ID,
		postShredOperator,
	); err == nil {
		t.Fatal("post-shred receipt committed without its signed companion")
	}
	if _, err := pool.Exec(
		ctx,
		`GRANT SELECT, INSERT ON public.ir_post_shred_attempt_records
		 TO probectl_provider`,
	); err != nil {
		t.Fatal(err)
	}
	var postShredEventsAfterFailedWrite int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM public.provider_audit_events WHERE action = $1`,
		ActionIRPostShredRevealDenied,
	).Scan(&postShredEventsAfterFailedWrite); err != nil {
		t.Fatal(err)
	}
	if postShredEventsAfterFailedWrite != postShredEventsBefore {
		t.Fatal("failed signed tombstone write left a provider event")
	}

	if err := sidecar.RecordIRPostShredRevealAttempt(
		ctx,
		tenantA.ID,
		postShredOperator,
	); err != nil {
		t.Fatalf("record post-shred IR reveal denial: %v", err)
	}
	var (
		attemptAt    time.Time
		operator     string
		surface      string
		outcome      string
		target       string
		providerData []byte
		storedRow    []byte
	)
	if err := pool.QueryRow(
		ctx,
		`SELECT r.attempt_at, r.operator, r.surface, r.outcome,
		        e.target, e.data::text::bytea, row_to_json(r)::text::bytea
		   FROM public.ir_post_shred_attempt_records r
		   JOIN public.provider_audit_events e
		     ON e.hash = r.provider_event_ref
		  WHERE r.tenant_id = $1::uuid`,
		tenantA.ID,
	).Scan(
		&attemptAt,
		&operator,
		&surface,
		&outcome,
		&target,
		&providerData,
		&storedRow,
	); err != nil {
		t.Fatal(err)
	}
	if attemptAt.IsZero() ||
		operator != postShredOperator ||
		surface != irPostShredSurface ||
		outcome != irPostShredOutcome ||
		target != tenantA.ID ||
		!bytes.Contains(providerData, []byte(`"outcome": "denied-post-shred"`)) {
		t.Fatalf(
			"post-shred tombstone projection = at=%s operator=%q surface=%q outcome=%q target=%q data=%s",
			attemptAt,
			operator,
			surface,
			outcome,
			target,
			providerData,
		)
	}
	for _, forbidden := range [][]byte{
		[]byte(attributions[tenantA.ID].Operator),
		[]byte(attributions[tenantA.ID].Grant),
		[]byte(attributions[tenantA.ID].Consent),
		[]byte(attributions[tenantA.ID].Reason),
		[]byte(events[tenantA.ID].Hash),
		artifacts[tenantA.ID].publicPEM,
		artifacts[tenantA.ID].sealedPrivate,
	} {
		if len(forbidden) > 0 && bytes.Contains(storedRow, forbidden) {
			t.Fatalf("post-shred tombstone retained shredded tenant attribution: %q", forbidden)
		}
	}
	assertIRCryptoShredArtifactsAbsent(t, artifacts[tenantA.ID])
	assertIRPostShredProviderIsolation(t, pool, tenantA.ID, tenantB.ID)
	if err := lifecycle.VerifyIRPostShredAttemptLedger(ctx); err != nil {
		t.Fatalf("verify signed post-shred IR attempt ledger: %v", err)
	}

	// An altered provider operator breaks the record signature. Restoring the
	// signed value makes verification pass again.
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_post_shred_attempt_records
		    SET operator = 'altered-operator'
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.VerifyIRPostShredAttemptLedger(ctx); err == nil {
		t.Fatal("startup verification accepted an altered post-shred tombstone")
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_post_shred_attempt_records
		    SET operator = $2
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
		postShredOperator,
	); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.VerifyIRPostShredAttemptLedger(ctx); err != nil {
		t.Fatalf("restored post-shred tombstone did not verify: %v", err)
	}

	// A tenant that never had an IR event or key artifact still needs an
	// honest, signed no-op plan/tombstone so verifiable deletion cannot become
	// permanently stuck on a key domain that never existed.
	emptyPlan, err := lifecycle.Plan(
		ctx,
		tenantWithoutKey.ID,
		"deletion-operator",
	)
	if err != nil {
		t.Fatalf("plan empty IR key domain: %v", err)
	}
	if err := lifecycle.Execute(
		ctx,
		tenantWithoutKey.ID,
		"deletion-operator",
		emptyPlan,
	); err != nil {
		t.Fatalf("execute empty IR key domain: %v", err)
	}
	assertIRCryptoShredLedgerCount(t, pool, tenantWithoutKey.ID, 2)
	if countingDestroyer.destroyCalls != 2 {
		t.Fatalf(
			"destroy calls after signed empty-domain receipt = %d, want 2",
			countingDestroyer.destroyCalls,
		)
	}
	if err := lifecycle.VerifyIRKeyShredLedger(ctx); err != nil {
		t.Fatalf("verify empty-domain key-shred ledger: %v", err)
	}

	for action, want := range map[string]int{
		ActionIRKeyDestroyFailed:    1,
		ActionIRKeyDestroyIntent:    1,
		ActionIRKeyDestroyCompleted: 1,
	} {
		var got int
		if err := pool.QueryRow(
			ctx,
			`SELECT count(*) FROM public.provider_audit_events
			  WHERE action = $1 AND target = $2`,
			action,
			tenantA.ID,
		).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s receipts = %d, want %d", action, got, want)
		}
	}

	// Restoring copied artifacts cannot reactivate a signed tombstoned domain.
	if err := os.WriteFile(
		artifacts[tenantA.ID].publicPath,
		artifacts[tenantA.ID].publicPEM,
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		artifacts[tenantA.ID].privatePath,
		artifacts[tenantA.ID].sealedPrivate,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := revealer.Reveal(
		ctx,
		tenantA.ID,
		events[tenantA.ID].Hash,
	); !errors.Is(err, ErrIRKeyUnavailable) {
		t.Fatalf("restored tenant-A artifact reveal = %v, want permanent denial", err)
	}

	// An owner alteration is detected by the signed record/head verifier.
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_key_shred_records
		    SET actor_hash = repeat('0', 64)
		  WHERE tenant_id = $1::uuid AND kind = 'plan'`,
		tenantA.ID,
	); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.VerifyIRKeyShredLedger(ctx); err == nil {
		t.Fatal("startup ledger verification accepted an altered plan")
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_key_shred_records
		    SET actor_hash = $2
		  WHERE tenant_id = $1::uuid AND kind = 'plan'`,
		tenantA.ID,
		hashIRKeyShredActor("deletion-operator"),
	); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.VerifyIRKeyShredLedger(ctx); err != nil {
		t.Fatalf("restored signed ledger did not verify: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`DELETE FROM public.ir_post_shred_attempt_records
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.VerifyIRPostShredAttemptLedger(ctx); err == nil {
		t.Fatal("startup verification accepted a removed post-shred tombstone")
	}
	if _, err := pool.Exec(
		ctx,
		`DELETE FROM public.ir_key_shred_records
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(
		ctx,
		`DELETE FROM public.ir_key_shred_heads
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.VerifyIRKeyShredLedger(ctx); err == nil {
		t.Fatal("startup ledger verification accepted removed plan/tombstone proof")
	}
}

type irCryptoShredTestArtifacts struct {
	publicPath    string
	privatePath   string
	publicPEM     []byte
	sealedPrivate []byte
}

type blockingIROpenResolver struct {
	delegate IROpenKeyResolver
	entered  chan struct{}
	release  <-chan struct{}
	once     sync.Once
}

type countingIRKeyArtifactDestroyer struct {
	delegate     crypto.KeyArtifactDestroyer
	destroyCalls int
}

func (d *countingIRKeyArtifactDestroyer) Inventory(
	ctx context.Context,
	subject string,
	keyIDs []string,
) (crypto.KeyArtifactManifest, error) {
	return d.delegate.Inventory(ctx, subject, keyIDs)
}

func (d *countingIRKeyArtifactDestroyer) Destroy(
	ctx context.Context,
	manifest crypto.KeyArtifactManifest,
) (crypto.KeyArtifactReceipt, error) {
	d.destroyCalls++
	return d.delegate.Destroy(ctx, manifest)
}

func (d *countingIRKeyArtifactDestroyer) VerifyDestroyed(
	ctx context.Context,
	manifest crypto.KeyArtifactManifest,
) error {
	return d.delegate.VerifyDestroyed(ctx, manifest)
}

func (r *blockingIROpenResolver) OpenProviderForTenant(
	ctx context.Context,
	tenantID, keyID string,
) (crypto.KeyProvider, func(), error) {
	r.once.Do(func() { close(r.entered) })
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-r.release:
	}
	return r.delegate.OpenProviderForTenant(ctx, tenantID, keyID)
}

func writeIRCryptoShredTestArtifacts(
	t *testing.T,
	ctx context.Context,
	unlock crypto.KeyProvider,
	publicDirectory, privateDirectory, tenantID string,
) irCryptoShredTestArtifacts {
	t.Helper()
	privatePEM, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	sealedPrivate, keyID, err := SealIRPrivateKeyArtifact(
		ctx,
		unlock,
		tenantID,
		privatePEM,
	)
	crypto.Zeroize(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	privateName, err := IRPrivateKeyArtifactFilename(tenantID, keyID)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := irCryptoShredTestArtifacts{
		publicPath:    filepath.Join(publicDirectory, tenantID+".pem"),
		privatePath:   filepath.Join(privateDirectory, privateName),
		publicPEM:     append([]byte(nil), publicPEM...),
		sealedPrivate: append([]byte(nil), sealedPrivate...),
	}
	if err := os.WriteFile(artifacts.publicPath, publicPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		artifacts.privatePath,
		sealedPrivate,
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	return artifacts
}

func assertIRCryptoShredArtifactsPresent(
	t *testing.T,
	artifacts irCryptoShredTestArtifacts,
) {
	t.Helper()
	for _, path := range []string{artifacts.publicPath, artifacts.privatePath} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("expected IR key artifact %q: %v", path, err)
		}
	}
}

func assertIRCryptoShredArtifactsAbsent(
	t *testing.T,
	artifacts irCryptoShredTestArtifacts,
) {
	t.Helper()
	for _, path := range []string{artifacts.publicPath, artifacts.privatePath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("IR key artifact %q remains: %v", path, err)
		}
	}
}

func assertIRCryptoShredLedgerCount(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID string,
	want int,
) {
	t.Helper()
	var got int
	if err := pool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM public.ir_key_shred_records
		  WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("tenant %s shred ledger rows = %d, want %d", tenantID, got, want)
	}
}

func assertIRCryptoShredProviderIsolation(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantA, tenantB string,
) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_provider`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		ctx,
		`SELECT set_config('probectl.tenant_id', $1, true)`,
		tenantA,
	); err != nil {
		t.Fatal(err)
	}
	var ownRecords, foreignRecords, foreignHeads int
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM public.ir_key_shred_records
		  WHERE tenant_id = $1::uuid`,
		tenantA,
	).Scan(&ownRecords); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM public.ir_key_shred_records
		  WHERE tenant_id = $1::uuid`,
		tenantB,
	).Scan(&foreignRecords); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM public.ir_key_shred_heads
		  WHERE tenant_id = $1::uuid`,
		tenantB,
	).Scan(&foreignHeads); err != nil {
		t.Fatal(err)
	}
	if ownRecords != 2 || foreignRecords != 0 || foreignHeads != 0 {
		t.Fatalf(
			"tenant-A provider scope saw own=%d foreign_records=%d foreign_heads=%d",
			ownRecords,
			foreignRecords,
			foreignHeads,
		)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT ir_shred_insert_denied`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO public.ir_key_shred_records
		    (tenant_id, chain_pos, kind, plan_ref, covered_seq,
		     ir_record_count, ir_last_audit_seq, ir_last_hash,
		     artifact_manifest, actor_hash, event_ref, destroyed_count,
		     destroy_receipt_hash, prev_hash, hash, signature)
		 SELECT $2::uuid, chain_pos, kind, plan_ref, covered_seq,
		        ir_record_count, ir_last_audit_seq, ir_last_hash,
		        artifact_manifest, actor_hash, event_ref, destroyed_count,
		        destroy_receipt_hash, prev_hash, hash, signature
		   FROM public.ir_key_shred_records
		  WHERE tenant_id = $1::uuid AND kind = 'plan'`,
		tenantA,
		tenantB,
	); err == nil {
		t.Fatal("tenant-A provider scope inserted a tenant-B shred plan")
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT ir_shred_insert_denied`); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{
		`UPDATE public.ir_key_shred_records
		    SET actor_hash = actor_hash
		  WHERE tenant_id = $1::uuid`,
		`DELETE FROM public.ir_key_shred_records
		  WHERE tenant_id = $1::uuid`,
	} {
		if _, err := tx.Exec(ctx, `SAVEPOINT ir_shred_mutation_denied`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, operation, tenantA); err == nil {
			t.Fatalf("provider runtime mutation unexpectedly succeeded: %s", operation)
		}
		if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT ir_shred_mutation_denied`); err != nil {
			t.Fatal(err)
		}
	}
}

func assertIRPostShredProviderIsolation(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantA, tenantB string,
) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_provider`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		ctx,
		`SELECT set_config('probectl.tenant_id', $1, true)`,
		tenantA,
	); err != nil {
		t.Fatal(err)
	}
	var ownRecords, foreignRecords, foreignHeads int
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM public.ir_post_shred_attempt_records
		  WHERE tenant_id = $1::uuid`,
		tenantA,
	).Scan(&ownRecords); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM public.ir_post_shred_attempt_records
		  WHERE tenant_id = $1::uuid`,
		tenantB,
	).Scan(&foreignRecords); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM public.ir_post_shred_attempt_heads
		  WHERE tenant_id = $1::uuid`,
		tenantB,
	).Scan(&foreignHeads); err != nil {
		t.Fatal(err)
	}
	if ownRecords != 1 || foreignRecords != 0 || foreignHeads != 0 {
		t.Fatalf(
			"tenant-A provider scope saw own=%d foreign_records=%d foreign_heads=%d",
			ownRecords,
			foreignRecords,
			foreignHeads,
		)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT ir_post_shred_insert_denied`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO public.ir_post_shred_attempt_records
		    (tenant_id, chain_pos, attempt_at, operator, surface, outcome,
		     provider_event_ref, prev_hash, hash, signature)
		 SELECT $2::uuid, chain_pos, attempt_at, operator, surface, outcome,
		        provider_event_ref, prev_hash, hash, signature
		   FROM public.ir_post_shred_attempt_records
		  WHERE tenant_id = $1::uuid`,
		tenantA,
		tenantB,
	); err == nil {
		t.Fatal("tenant-A provider scope inserted a tenant-B post-shred tombstone")
	}
	if _, err := tx.Exec(
		ctx,
		`ROLLBACK TO SAVEPOINT ir_post_shred_insert_denied`,
	); err != nil {
		t.Fatal(err)
	}
}
