// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	// ErrIRAttributionNotFound deliberately conflates absence with an
	// other-tenant event reference.
	ErrIRAttributionNotFound = errors.New("audit: IR attribution not found")
	// ErrIRKeyUnavailable means the investigation-only opener is not mounted.
	ErrIRKeyUnavailable = errors.New("audit: IR investigation key unavailable")
)

// IRRevealer is the investigation-only read capability. It is constructed
// separately from IRStagePG's steady-state writer and resolves private key
// material only after tenant-first authorization at the control-plane edge.
type IRRevealer struct {
	worm    *WormExporter
	sidecar *IRStagePG
	keys    IROpenKeyResolver
}

// NewIRRevealer binds reveal to the exact WORM exporter and sidecar used by
// the provider runtime. keys may be nil while the offline opener is unmounted;
// in that state Reveal fails closed with ErrIRKeyUnavailable.
func NewIRRevealer(
	worm *WormExporter,
	sidecar *IRStagePG,
	keys IROpenKeyResolver,
) (*IRRevealer, error) {
	if worm == nil || sidecar == nil || worm.objects == nil {
		return nil, errors.New("audit: IR reveal durability dependencies are unavailable")
	}
	return &IRRevealer{worm: worm, sidecar: sidecar, keys: keys}, nil
}

// Reveal opens one retained attribution after proving its tenant-routed stage,
// signed WORM segment, encrypted companion, and signed coverage record agree.
func (r *IRRevealer) Reveal(
	ctx context.Context,
	tenantID, eventRef string,
) (IRAttribution, error) {
	if r == nil || r.worm == nil || r.sidecar == nil {
		return IRAttribution{}, errors.New("audit: IR revealer is unavailable")
	}
	if r.keys == nil {
		return IRAttribution{}, ErrIRKeyUnavailable
	}
	if !canonicalIRTenantID.MatchString(tenantID) ||
		!irLowerHex64.MatchString(eventRef) {
		return IRAttribution{}, ErrIRAttributionNotFound
	}
	// This verifies the full continuous coverage chain/head and every exact
	// WORM+companion object before returning a retention-authorizing cursor.
	covered, err := r.sidecar.CoverageWatermark(
		ctx,
		r.worm.objects,
		r.worm.readVerifiedWORMSegment,
	)
	if err != nil {
		return IRAttribution{}, fmt.Errorf(
			"audit: verify IR WORM coverage before reveal: %w",
			err,
		)
	}

	var attribution IRAttribution
	err = tenancy.InProvider(
		ctx,
		r.sidecar.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			return withIRTenantRoute(ctx, q, tenantID, func() error {
				// Keep the same database advisory lock from ledger check through
				// the final Open. Planning therefore cannot commit between an
				// "active" check and use of the investigation-only key.
				if err := lockIRTenant(ctx, q, tenantID); err != nil {
					return err
				}
				if err := r.sidecar.assertIRKeyActiveTx(
					ctx,
					q,
					tenantID,
				); err != nil {
					return err
				}
				if _, err := r.sidecar.verifiedIRStageSnapshotTx(
					ctx,
					q,
					tenantID,
				); err != nil {
					return fmt.Errorf(
						"audit: verify tenant IR chain before reveal: %w",
						err,
					)
				}
				stage, err := r.sidecar.readIRStageByEventRef(
					ctx,
					q,
					tenantID,
					eventRef,
				)
				if err != nil {
					return err
				}
				if stage.AuditSeq > covered {
					return errors.New(
						"audit: IR attribution is not yet covered by durable WORM evidence",
					)
				}
				coverage, err := r.sidecar.readIRCoverageForSeq(
					ctx,
					q,
					stage.AuditSeq,
				)
				if err != nil {
					return err
				}
				if err := r.sidecar.verifyIRCoverageRecord(coverage); err != nil {
					return err
				}
				opened, err := r.openCoveredStage(
					ctx,
					tenantID,
					eventRef,
					stage,
					coverage,
				)
				if err != nil {
					return err
				}
				attribution = opened
				return nil
			})
		},
	)
	if err != nil {
		return IRAttribution{}, err
	}
	return attribution, nil
}

func (r *IRRevealer) openCoveredStage(
	ctx context.Context,
	tenantID, eventRef string,
	stage irStoredStage,
	coverage irCoverageRecord,
) (IRAttribution, error) {
	wormKey := fmt.Sprintf(
		"%ssegment-%012d-%012d.json",
		wormPrefix,
		coverage.FromSeq,
		coverage.ToSeq,
	)
	verified, err := r.worm.readVerifiedWORMSegment(
		ctx,
		wormKey,
		coverage.WORMSegmentHash,
	)
	if err != nil {
		return IRAttribution{}, fmt.Errorf("audit: verify reveal WORM segment: %w", err)
	}
	index := stage.AuditSeq - verified.segment.FromSeq
	if index < 0 || index >= int64(len(verified.segment.Events)) {
		return IRAttribution{}, errors.New(
			"audit: IR stage sequence is outside its covered WORM segment",
		)
	}
	wormEvent := verified.segment.Events[index]
	protected, err := classifyIRWORMAction(wormEvent.Action)
	if err != nil || !protected || wormEvent.Hash != eventRef {
		return IRAttribution{}, errors.New(
			"audit: IR stage differs from its protected WORM event",
		)
	}

	object, err := r.worm.objects.GetLimited(
		ctx,
		coverage.CompanionKey,
		maxIRWORMCompanionBytes,
	)
	if err != nil {
		return IRAttribution{}, fmt.Errorf(
			"audit: read IR reveal companion: %w",
			err,
		)
	}
	if object.ContentType != irWORMCompanionContentType ||
		hex.EncodeToString(crypto.Hash(object.Data)) != coverage.CompanionHash {
		return IRAttribution{}, errors.New(
			"audit: IR reveal companion differs from signed coverage",
		)
	}
	companion, err := r.sidecar.decodeAndVerifyIRWORMCompanion(
		object.Data,
		verified.segment,
		coverage.WORMSegmentHash,
	)
	if err != nil {
		return IRAttribution{}, err
	}
	if int64(len(companion.Records)) != coverage.ProtectedRecords {
		return IRAttribution{}, errors.New(
			"audit: IR reveal companion count differs from signed coverage",
		)
	}
	var binding *IRWORMCompanionRecord
	for index := range companion.Records {
		if companion.Records[index].AuditSeq == stage.AuditSeq {
			binding = &companion.Records[index]
			break
		}
	}
	if binding == nil || binding.StageHash != stage.Hash {
		return IRAttribution{}, errors.New(
			"audit: IR reveal companion lacks the tenant stage",
		)
	}
	wantBindingHash, err := hashCanonical(irWORMRecordHash{
		Domain: irWORMBindingDomain, TenantID: tenantID,
		AuditSeq: stage.AuditSeq, WORMSegmentHash: coverage.WORMSegmentHash,
		StageHash: stage.Hash, KeyID: binding.KeyID,
		WrappedDEK: binding.WrappedDEK, Ciphertext: binding.Ciphertext,
	})
	if err != nil {
		return IRAttribution{}, err
	}
	if binding.Hash != wantBindingHash {
		return IRAttribution{}, ErrIRAttributionNotFound
	}
	if err := r.sidecar.verifyIRStageRecord(tenantID, stage); err != nil {
		return IRAttribution{}, err
	}

	outerProvider, outerCleanup, err := r.keys.OpenProviderForTenant(
		ctx,
		tenantID,
		binding.KeyID,
	)
	if err != nil {
		return IRAttribution{}, normalizeIROpenError(err)
	}
	encodedStage, err := crypto.NewEnvelope(outerProvider).Open(
		ctx,
		crypto.Sealed{
			KeyID:      binding.KeyID,
			WrappedDEK: binding.WrappedDEK,
			Ciphertext: binding.Ciphertext,
		},
		irWORMStageAAD(tenantID, stage.AuditSeq, coverage.WORMSegmentHash),
	)
	outerCleanup()
	if err != nil {
		return IRAttribution{}, fmt.Errorf("audit: open IR WORM binding: %w", err)
	}
	defer crypto.Zeroize(encodedStage)
	expectedStage, err := (crypto.Sealed{
		KeyID:      stage.KeyID,
		WrappedDEK: stage.WrappedDEK,
		Ciphertext: stage.Ciphertext,
	}).Encode()
	if err != nil {
		return IRAttribution{}, err
	}
	defer crypto.Zeroize(expectedStage)
	if !bytes.Equal(encodedStage, expectedStage) {
		return IRAttribution{}, errors.New(
			"audit: IR WORM binding does not contain its indexed stage",
		)
	}
	innerSealed, err := crypto.DecodeSealed(encodedStage)
	if err != nil {
		return IRAttribution{}, fmt.Errorf("audit: decode IR stage envelope: %w", err)
	}
	innerProvider, innerCleanup, err := r.keys.OpenProviderForTenant(
		ctx,
		tenantID,
		innerSealed.KeyID,
	)
	if err != nil {
		return IRAttribution{}, normalizeIROpenError(err)
	}
	plaintext, err := crypto.NewEnvelope(innerProvider).Open(
		ctx,
		innerSealed,
		irStageAAD(tenantID, stage.AuditSeq, eventRef),
	)
	innerCleanup()
	if err != nil {
		return IRAttribution{}, fmt.Errorf("audit: open IR attribution: %w", err)
	}
	defer crypto.Zeroize(plaintext)
	var attribution IRAttribution
	if err := json.Unmarshal(plaintext, &attribution); err != nil {
		return IRAttribution{}, fmt.Errorf("audit: decode IR attribution: %w", err)
	}
	if err := validateOpenedIRAttribution(attribution, tenantID, eventRef); err != nil {
		return IRAttribution{}, err
	}
	return attribution, nil
}

func (s *IRStagePG) readIRStageByEventRef(
	ctx context.Context,
	q tenancy.Querier,
	tenantID, eventRef string,
) (irStoredStage, error) {
	var stage irStoredStage
	err := withIRTenantRoute(ctx, q, tenantID, func() error {
		err := q.QueryRow(
			ctx,
			`SELECT audit_seq, chain_pos, event_ref, key_id, wrapped_dek,
			        ciphertext, prev_hash, hash, signature
			   FROM ir_attribution_records
			  WHERE tenant_id = $1::uuid AND event_ref = $2`,
			tenantID,
			eventRef,
		).Scan(
			&stage.AuditSeq,
			&stage.ChainPos,
			&stage.EventRef,
			&stage.KeyID,
			&stage.WrappedDEK,
			&stage.Ciphertext,
			&stage.PrevHash,
			&stage.Hash,
			&stage.Signature,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrIRAttributionNotFound
		}
		return err
	})
	if err != nil {
		return irStoredStage{}, err
	}
	return stage, nil
}

func (s *IRStagePG) readIRCoverageForSeq(
	ctx context.Context,
	q tenancy.Querier,
	auditSeq int64,
) (irCoverageRecord, error) {
	var record irCoverageRecord
	err := q.QueryRow(
		ctx,
		`SELECT from_seq, to_seq, worm_segment_hash, companion_key,
		        companion_hash, protected_records, prev_hash, hash, signature
		   FROM public.ir_attribution_worm_coverage
		  WHERE from_seq <= $1 AND to_seq >= $1`,
		auditSeq,
	).Scan(
		&record.FromSeq,
		&record.ToSeq,
		&record.WORMSegmentHash,
		&record.CompanionKey,
		&record.CompanionHash,
		&record.ProtectedRecords,
		&record.PrevHash,
		&record.Hash,
		&record.Signature,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return irCoverageRecord{}, errors.New(
			"audit: IR attribution is not covered by durable WORM evidence",
		)
	}
	if err != nil {
		return irCoverageRecord{}, err
	}
	return record, nil
}

func validateOpenedIRAttribution(
	attribution IRAttribution,
	tenantID, eventRef string,
) error {
	if attribution.TenantID != tenantID ||
		attribution.EventRef != eventRef ||
		attribution.TS.IsZero() {
		return ErrIRAttributionNotFound
	}
	for _, field := range []struct {
		value string
		max   int
	}{
		{attribution.Operator, maxIRIdentityBytes},
		{attribution.TenantID, 128},
		{attribution.Grant, maxIRGrantBytes},
		{attribution.Surface, maxIRSurfaceBytes},
		{attribution.Consent, maxIRConsentBytes},
		{attribution.Outcome, maxIROutcomeBytes},
		{attribution.Reason, maxIRReasonBytes},
		{attribution.EventRef, 64},
	} {
		if strings.TrimSpace(field.value) == "" || len(field.value) > field.max {
			return errors.New("audit: opened IR attribution has an invalid shape")
		}
	}
	return nil
}

func normalizeIROpenError(err error) error {
	if errors.Is(err, ErrIRKeyUnavailable) ||
		errors.Is(err, crypto.ErrUnwrapUnavailable) ||
		errors.Is(err, os.ErrNotExist) {
		return ErrIRKeyUnavailable
	}
	return err
}
