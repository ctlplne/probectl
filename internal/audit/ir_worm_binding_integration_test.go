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
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

type integrationIRWORMKeys map[string]crypto.KeyProvider

func (k integrationIRWORMKeys) WrapProviderForTenant(
	_ context.Context,
	tenantID string,
) (crypto.KeyProvider, error) {
	provider, ok := k[tenantID]
	if !ok {
		return nil, errors.New("test IR public wrapping key is unavailable")
	}
	return provider, nil
}

func TestIRWORMCoverageRetentionAndReconstruction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	pool := isolatedIRWORMDatabase(t)

	tenantA, err := store.NewTenants(pool).Create(
		ctx,
		"ir-worm-a",
		"IR WORM A",
	)
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := store.NewTenants(pool).Create(
		ctx,
		"ir-worm-b",
		"IR WORM B",
	)
	if err != nil {
		t.Fatal(err)
	}
	irPrivate, irPublic, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	wrapOnly, err := crypto.NewRSAOAEPWrapProviderPEM(irPublic)
	if err != nil {
		t.Fatal(err)
	}
	investigator, err := crypto.NewRSAOAEPKeyProviderPEM(irPrivate)
	if err != nil {
		t.Fatal(err)
	}
	signingPrivate, signingPublic, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	sidecar, err := NewIRStagePG(
		pool,
		integrationIRWORMKeys{
			tenantA.ID: wrapOnly,
			tenantB.ID: wrapOnly,
		},
		signingPrivate,
		signingPublic,
	)
	if err != nil {
		t.Fatal(err)
	}

	ordinaryEvent, err := ProviderAppend(
		ctx,
		pool,
		"provider-system",
		"provider.tenant_status",
		tenantA.ID,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	rawNow := time.Now().UTC()
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.provider_audit_events
		    SET created_at = $1
		  WHERE seq = $2`,
		rawNow.Add(-48*time.Hour),
		ordinaryEvent.Seq,
	); err != nil {
		t.Fatal(err)
	}
	if n, err := PruneProvider(
		ctx,
		pool,
		RetentionPolicy{Window: 24 * time.Hour},
		ordinaryEvent.Seq,
		rawNow,
	); err == nil || n != 0 ||
		!strings.Contains(err.Error(), "verified WORM proof") {
		t.Fatalf(
			"zero-coverage raw prune = (%d, %v), want verified-proof refusal",
			n,
			err,
		)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.provider_audit_events
		    SET created_at = $1
		  WHERE seq = $2`,
		rawNow,
		ordinaryEvent.Seq,
	); err != nil {
		t.Fatal(err)
	}
	if n, err := pruneProviderWithProof(
		ctx,
		pool,
		RetentionPolicy{Window: 24 * time.Hour},
		ProviderRetentionProof{
			watermark: ordinaryEvent.Seq,
			verified:  true,
		},
		rawNow,
	); err != nil || n != 0 {
		t.Fatalf(
			"verified WORM-only core prune = (%d, %v), want (0, nil)",
			n,
			err,
		)
	}
	const canary = "ir-worm-canary-operator@example.test"
	attribution := IRAttribution{
		Operator: canary,
		TenantID: tenantA.ID,
		Grant:    "grant-ir-worm-a",
		Surface:  "results.latest",
		Consent:  "tenant-approved:tenant-admin-a",
		Outcome:  "accessed",
		Reason:   "investigate routed outage",
	}
	protectedEvent, err := ProviderAppendBreakGlass(
		ctx,
		pool,
		sidecar,
		canary,
		"provider.breakglass_access",
		attribution.Grant,
		map[string]any{
			"tenant":  tenantA.ID,
			"surface": attribution.Surface,
			"reason":  attribution.Reason,
		},
		attribution,
	)
	if err != nil {
		t.Fatal(err)
	}
	var firstOuter, secondOuter IRWORMCompanionRecord
	if err := tenancy.InProvider(
		ctx,
		pool,
		func(ctx context.Context, q tenancy.Querier) error {
			const segmentHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			firstOuter, err = sidecar.buildIRWORMRecord(
				ctx,
				q,
				protectedEvent,
				segmentHash,
			)
			if err != nil {
				return err
			}
			secondOuter, err = sidecar.buildIRWORMRecord(
				ctx,
				q,
				protectedEvent,
				segmentHash,
			)
			return err
		},
	); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstOuter.Ciphertext, secondOuter.Ciphertext) ||
		bytes.Equal(firstOuter.WrappedDEK, secondOuter.WrappedDEK) {
		t.Fatal("identical IR stage produced linkable outer WORM ciphertext")
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
	if n, err := worm.ExportOnce(ctx); err != nil || n != 2 {
		t.Fatalf("IR WORM export = (%d, %v), want (2, nil)", n, err)
	}
	segmentKey := fmt.Sprintf(
		"%ssegment-%012d-%012d.json",
		wormPrefix,
		1,
		protectedEvent.Seq,
	)
	verified, err := worm.readVerifiedWORMSegment(ctx, segmentKey, "")
	if err != nil {
		t.Fatal(err)
	}
	var bindWG sync.WaitGroup
	bindErrors := make(chan error, 2)
	for range 2 {
		bindWG.Add(1)
		go func() {
			defer bindWG.Done()
			bindErrors <- sidecar.PersistWORMCompanion(
				ctx,
				objects,
				verified,
			)
		}()
	}
	bindWG.Wait()
	close(bindErrors)
	for err := range bindErrors {
		if err != nil {
			t.Fatalf("concurrent IR WORM binder: %v", err)
		}
	}
	worm.WithIRWORMDurability(sidecar)
	if err := worm.VerifyWORMChain(ctx); err != nil {
		t.Fatalf("verify WORM+IR chain: %v", err)
	}
	if watermark, err := worm.RetentionWatermark(ctx); err != nil ||
		watermark != protectedEvent.Seq {
		t.Fatalf(
			"combined retention watermark = (%d, %v), want (%d, nil)",
			watermark,
			err,
			protectedEvent.Seq,
		)
	}

	companionKey := irWORMCompanionKey(1, protectedEvent.Seq)
	companionObject, err := objects.Get(ctx, companionKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(companionObject.Data, []byte(canary)) {
		t.Fatal("plaintext attribution canary appears in IR WORM companion")
	}
	if bytes.Contains(companionObject.Data, []byte(tenantA.ID)) ||
		bytes.Contains(companionObject.Data, []byte(tenantB.ID)) {
		t.Fatal("plaintext tenant linkage appears in IR WORM companion")
	}
	wormObject, err := objects.Get(
		ctx,
		segmentKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wormObject.Data, []byte(canary)) {
		t.Fatal("plaintext attribution canary appears in minimized WORM bytes")
	}
	var companion IRWORMCompanion
	if err := json.Unmarshal(companionObject.Data, &companion); err != nil {
		t.Fatal(err)
	}
	if len(companion.Records) != 1 {
		t.Fatalf("protected companion records = %d, want 1", len(companion.Records))
	}
	reconstructed := openIntegrationIRWORMAttribution(
		t,
		investigator,
		tenantA.ID,
		companion.Records[0],
		companion.WORMSegmentHash,
		protectedEvent.Hash,
	)
	assertIntegrationIRAttribution(t, reconstructed, attribution)

	wrongAAD := irWORMStageAAD(
		tenantB.ID,
		protectedEvent.Seq,
		companion.WORMSegmentHash,
	)
	if _, err := crypto.NewEnvelope(investigator).Open(
		ctx,
		crypto.Sealed{
			KeyID:      companion.Records[0].KeyID,
			WrappedDEK: companion.Records[0].WrappedDEK,
			Ciphertext: companion.Records[0].Ciphertext,
		},
		wrongAAD,
	); err == nil {
		t.Fatal("tenant-B AAD opened tenant-A IR WORM binding")
	}

	// A missing or changed finalized companion and a changed signed watermark
	// must each hold retention closed.
	tamperedCompanion := companion
	tamperedCompanion.Records = append(
		[]IRWORMCompanionRecord(nil),
		companion.Records...,
	)
	tamperedCompanion.Records[0].Ciphertext = append(
		[]byte(nil),
		tamperedCompanion.Records[0].Ciphertext...,
	)
	tamperedCompanion.Records[0].Ciphertext[0] ^= 0x01
	tamperedRaw, err := json.Marshal(tamperedCompanion)
	if err != nil {
		t.Fatal(err)
	}
	if err := objects.Put(
		ctx,
		companionKey,
		companionObject.ContentType,
		tamperedRaw,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := worm.RetentionWatermark(ctx); err == nil {
		t.Fatal("altered finalized IR WORM companion produced a watermark")
	}
	if err := objects.Put(
		ctx,
		companionKey,
		companionObject.ContentType,
		companionObject.Data,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := objects.DeletePrefix(ctx, companionKey); err != nil {
		t.Fatal(err)
	}
	if _, err := worm.RetentionWatermark(ctx); err == nil {
		t.Fatal("missing finalized IR WORM companion produced a watermark")
	}
	if err := objects.Put(
		ctx,
		companionKey,
		companionObject.ContentType,
		companionObject.Data,
	); err != nil {
		t.Fatal(err)
	}
	var coveredSeq int64
	var lastHash, companionHash string
	var headSignature []byte
	if err := pool.QueryRow(
		ctx,
		`SELECT covered_seq, last_hash, companion_hash, signature
		   FROM public.ir_attribution_worm_coverage_head
		  WHERE singleton`,
	).Scan(
		&coveredSeq,
		&lastHash,
		&companionHash,
		&headSignature,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_attribution_worm_coverage_head
		    SET covered_seq = covered_seq - 1
		  WHERE singleton`,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := worm.RetentionWatermark(ctx); err == nil {
		t.Fatal("altered IR WORM coverage head produced a watermark")
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_attribution_worm_coverage_head
		    SET covered_seq = $1,
		        last_hash = $2,
		        companion_hash = $3,
		        signature = $4
		  WHERE singleton`,
		coveredSeq,
		lastHash,
		companionHash,
		headSignature,
	); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.provider_audit_events
		    SET created_at = $1`,
		now.Add(-48*time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if n, err := PruneProvider(
		ctx,
		pool,
		RetentionPolicy{Window: 24 * time.Hour},
		protectedEvent.Seq,
		now,
	); err == nil || n != 0 ||
		!strings.Contains(err.Error(), "verified WORM proof") {
		t.Fatalf("raw-integer IR prune = (%d, %v), want proof refusal", n, err)
	}
	runner := NewRetentionRunnerPG(
		pool,
		RetentionPolicy{Window: 24 * time.Hour},
		nil,
		testLog(),
	).WithProviderRetentionProof(worm.RetentionProof)
	summary, err := runner.Tick(ctx)
	if err != nil {
		t.Fatalf("verified IR retention pass: %v", err)
	}
	if summary.ProviderPruned != protectedEvent.Seq {
		t.Fatalf(
			"provider rows pruned = %d, want %d",
			summary.ProviderPruned,
			protectedEvent.Seq,
		)
	}
	var retainedPrimary, retainedStage int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM public.provider_audit_events
		  WHERE seq = $1`,
		protectedEvent.Seq,
	).Scan(&retainedPrimary); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM public.ir_attribution_records
		  WHERE tenant_id = $1::uuid AND audit_seq = $2`,
		tenantA.ID,
		protectedEvent.Seq,
	).Scan(&retainedStage); err != nil {
		t.Fatal(err)
	}
	if retainedPrimary != 0 || retainedStage != 1 {
		t.Fatalf(
			"post-prune primary/stage rows = %d/%d, want 0/1",
			retainedPrimary,
			retainedStage,
		)
	}
	afterPrune, err := objects.Get(ctx, companionKey)
	if err != nil {
		t.Fatalf("retention removed IR WORM companion: %v", err)
	}
	if !bytes.Equal(afterPrune.Data, companionObject.Data) {
		t.Fatal("retention changed IR WORM companion bytes")
	}
	reconstructed = openIntegrationIRWORMAttribution(
		t,
		investigator,
		tenantA.ID,
		companion.Records[0],
		companion.WORMSegmentHash,
		protectedEvent.Hash,
	)
	assertIntegrationIRAttribution(t, reconstructed, attribution)

	// The prune receipt is ordinary provider evidence. It still receives a
	// signed empty companion so coverage remains continuous across segments
	// that contain no protected action.
	if n, err := worm.ExportOnce(ctx); err != nil || n != 1 {
		t.Fatalf("zero-protected receipt export = (%d, %v), want (1, nil)", n, err)
	}
	emptyObject, err := objects.Get(
		ctx,
		irWORMCompanionKey(protectedEvent.Seq+1, protectedEvent.Seq+1),
	)
	if err != nil {
		t.Fatal(err)
	}
	var emptyCompanion IRWORMCompanion
	if err := json.Unmarshal(emptyObject.Data, &emptyCompanion); err != nil {
		t.Fatal(err)
	}
	if len(emptyCompanion.Records) != 0 {
		t.Fatalf(
			"ordinary WORM segment companion records = %d, want 0",
			len(emptyCompanion.Records),
		)
	}
	if watermark, err := worm.RetentionWatermark(ctx); err != nil ||
		watermark != protectedEvent.Seq+1 {
		t.Fatalf(
			"zero-protected coverage watermark = (%d, %v), want (%d, nil)",
			watermark,
			err,
			protectedEvent.Seq+1,
		)
	}
	var stageCount, stageLastSeq int64
	var stageLastHash string
	var stageSignature []byte
	if err := pool.QueryRow(
		ctx,
		`SELECT record_count, last_audit_seq, last_hash, head_signature
		   FROM public.ir_attribution_heads
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	).Scan(
		&stageCount,
		&stageLastSeq,
		&stageLastHash,
		&stageSignature,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_attribution_heads
		    SET last_hash = repeat('b', 64)
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := worm.RetentionWatermark(ctx); err == nil {
		t.Fatal("altered routed IR stage head produced a retention watermark")
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.ir_attribution_heads
		    SET record_count = $2,
		        last_audit_seq = $3,
		        last_hash = $4,
		        head_signature = $5
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
		stageCount,
		stageLastSeq,
		stageLastHash,
		stageSignature,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(
		ctx,
		`DELETE FROM public.ir_attribution_records
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(
		ctx,
		`DELETE FROM public.ir_attribution_heads
		  WHERE tenant_id = $1::uuid`,
		tenantA.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := worm.RetentionWatermark(ctx); err == nil {
		t.Fatal("whole-stage-chain removal produced an IR retention watermark")
	}
}

func openIntegrationIRWORMAttribution(
	t *testing.T,
	investigator crypto.KeyProvider,
	tenantID string,
	record IRWORMCompanionRecord,
	segmentHash, eventRef string,
) IRAttribution {
	t.Helper()
	ctx := context.Background()
	outer, err := crypto.NewEnvelope(investigator).Open(
		ctx,
		crypto.Sealed{
			KeyID:      record.KeyID,
			WrappedDEK: record.WrappedDEK,
			Ciphertext: record.Ciphertext,
		},
		irWORMStageAAD(tenantID, record.AuditSeq, segmentHash),
	)
	if err != nil {
		t.Fatalf("open outer IR WORM binding: %v", err)
	}
	inner, err := crypto.DecodeSealed(outer)
	crypto.Zeroize(outer)
	if err != nil {
		t.Fatalf("decode inner IR stage: %v", err)
	}
	plaintext, err := crypto.NewEnvelope(investigator).Open(
		ctx,
		inner,
		irStageAAD(tenantID, record.AuditSeq, eventRef),
	)
	if err != nil {
		t.Fatalf("open inner IR stage: %v", err)
	}
	defer crypto.Zeroize(plaintext)
	var attribution IRAttribution
	if err := json.Unmarshal(plaintext, &attribution); err != nil {
		t.Fatalf("decode reconstructed attribution: %v", err)
	}
	return attribution
}

func assertIntegrationIRAttribution(
	t *testing.T,
	got, want IRAttribution,
) {
	t.Helper()
	if got.Operator != want.Operator ||
		got.TenantID != want.TenantID ||
		got.Grant != want.Grant ||
		got.Surface != want.Surface ||
		got.Consent != want.Consent ||
		got.Outcome != want.Outcome ||
		got.Reason != want.Reason ||
		got.EventRef == "" ||
		got.TS.IsZero() {
		t.Fatalf("reconstructed attribution = %#v, want semantic match %#v", got, want)
	}
}

func isolatedIRWORMDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	adminConfig, err := pgxpool.ParseConfig(testsupport.PostgresDSN())
	if err != nil {
		t.Fatalf("parse postgres DSN: %v", err)
	}
	adminConfig.ConnConfig.Database = "postgres"
	admin, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		testsupport.SkipOrFatal(t, "open postgres admin connection: %v", err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	database := fmt.Sprintf("probectl_ir_worm_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+quoted); err != nil {
		admin.Close()
		t.Fatalf("create isolated IR WORM database: %v", err)
	}
	testConfig := adminConfig.Copy()
	testConfig.ConnConfig.Database = database
	pool, err := pgxpool.NewWithConfig(ctx, testConfig)
	if err != nil {
		_, _ = admin.Exec(ctx, `DROP DATABASE `+quoted+` WITH (FORCE)`)
		admin.Close()
		t.Fatalf("open isolated IR WORM database: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		_, _ = admin.Exec(ctx, `DROP DATABASE `+quoted+` WITH (FORCE)`)
		admin.Close()
		t.Fatalf("ping isolated IR WORM database: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		_, _ = admin.Exec(ctx, `DROP DATABASE `+quoted+` WITH (FORCE)`)
		admin.Close()
		t.Fatalf("migrate isolated IR WORM database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(
			context.Background(),
			`DROP DATABASE IF EXISTS `+quoted+` WITH (FORCE)`,
		)
		admin.Close()
	})
	return pool
}
