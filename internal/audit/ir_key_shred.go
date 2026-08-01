// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	irKeyShredRecordDomain  = "probectl-ir-key-shred-record-v1"
	irKeyShredHeadDomain    = "probectl-ir-key-shred-head-v1"
	irKeyShredReceiptDomain = "probectl-ir-key-shred-receipt-v1"

	ActionIRKeyDestroyIntent    = "lifecycle.ir_key_destroy_intent"
	ActionIRKeyDestroyCompleted = "lifecycle.ir_key_destroy_completed"
	ActionIRKeyDestroyFailed    = "lifecycle.ir_key_destroy_failed"

	irKeyShredFailureTimeout = 5 * time.Second
)

type irKeyShredRecord struct {
	TenantID           string
	ChainPos           int64
	Kind               string
	PlanRef            string
	CoveredSeq         int64
	IRRecordCount      int64
	IRLastAuditSeq     int64
	IRLastHash         string
	ArtifactManifest   crypto.KeyArtifactManifest
	ActorHash          string
	EventRef           string
	DestroyedCount     int64
	DestroyReceiptHash string
	PrevHash           string
	Hash               string
	Signature          []byte
}

type irKeyShredRecordHash struct {
	Domain             string                     `json:"domain"`
	TenantID           string                     `json:"tenant_id"`
	ChainPos           int64                      `json:"chain_pos"`
	Kind               string                     `json:"kind"`
	PlanRef            string                     `json:"plan_ref"`
	CoveredSeq         int64                      `json:"covered_seq"`
	IRRecordCount      int64                      `json:"ir_record_count"`
	IRLastAuditSeq     int64                      `json:"ir_last_audit_seq"`
	IRLastHash         string                     `json:"ir_last_hash"`
	ArtifactManifest   crypto.KeyArtifactManifest `json:"artifact_manifest"`
	ActorHash          string                     `json:"actor_hash"`
	EventRef           string                     `json:"event_ref"`
	DestroyedCount     int64                      `json:"destroyed_count"`
	DestroyReceiptHash string                     `json:"destroy_receipt_hash"`
	PrevHash           string                     `json:"prev_hash"`
}

type irKeyShredHead struct {
	RecordCount int64
	LastHash    string
	Signature   []byte
}

type irKeyShredHeadHash struct {
	Domain      string `json:"domain"`
	TenantID    string `json:"tenant_id"`
	RecordCount int64  `json:"record_count"`
	LastHash    string `json:"last_hash"`
}

type irKeyShredState struct {
	Plan      *irKeyShredRecord
	Tombstone *irKeyShredRecord
}

type irStageSnapshot struct {
	Head   irStageHead
	KeyIDs []string
}

// IRKeyLifecycle owns only the explicit, destructive investigation-key
// capability. The routine IR writer and revealer do not receive it.
type IRKeyLifecycle struct {
	worm      *WormExporter
	sidecar   *IRStagePG
	destroyer crypto.KeyArtifactDestroyer
}

// NewIRKeyLifecycle binds key destruction to the same signed WORM and sidecar
// instances used by the shipping provider runtime. A nil destroyer is allowed
// so steady-state operation can keep the IR private domain offline; Plan then
// fails closed until the operator mounts that capability for deletion.
func NewIRKeyLifecycle(
	worm *WormExporter,
	sidecar *IRStagePG,
	destroyer crypto.KeyArtifactDestroyer,
) (*IRKeyLifecycle, error) {
	if worm == nil || sidecar == nil || worm.objects == nil ||
		sidecar.pool == nil {
		return nil, errors.New("audit: IR key lifecycle durability dependencies are unavailable")
	}
	return &IRKeyLifecycle{
		worm: worm, sidecar: sidecar, destroyer: destroyer,
	}, nil
}

// Plan verifies the tenant's signed IR chain and complete WORM coverage,
// inventories the exact operator-owned artifacts, then atomically appends a
// provider intent event and signed plan. Once committed, the plan permanently
// freezes new attribution writes and reveals for this tenant.
func (l *IRKeyLifecycle) Plan(
	ctx context.Context,
	tenantID, actor string,
) (planID string, retErr error) {
	if err := validateIRKeyShredCaller(tenantID, actor); err != nil {
		return "", err
	}
	if l == nil || l.worm == nil || l.sidecar == nil ||
		l.sidecar.pool == nil {
		return "", errors.New("audit: IR key destruction capability is not mounted")
	}
	defer func() {
		if retErr == nil {
			return
		}
		receiptCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			irKeyShredFailureTimeout,
		)
		defer cancel()
		receiptErr := l.recordFailure(
			receiptCtx,
			tenantID,
			actor,
			"",
			"plan_failed",
		)
		retErr = errors.Join(retErr, receiptErr)
	}()
	if l.destroyer == nil {
		return "", errors.New("audit: IR key destruction capability is not mounted")
	}

	covered, err := l.sidecar.CoverageWatermark(
		ctx,
		l.worm.objects,
		l.worm.readVerifiedWORMSegment,
	)
	if err != nil {
		return "", fmt.Errorf("audit: verify IR coverage before key destruction: %w", err)
	}

	err = tenancy.InProvider(
		ctx,
		l.sidecar.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			if err := lockProviderStream(ctx, q); err != nil {
				return fmt.Errorf("audit: lock provider stream for IR key plan: %w", err)
			}
			return withIRTenantRoute(ctx, q, tenantID, func() error {
				if err := lockIRTenant(ctx, q, tenantID); err != nil {
					return err
				}
				state, err := l.sidecar.verifyIRKeyShredStateTx(
					ctx,
					q,
					tenantID,
					true,
				)
				if err != nil {
					return err
				}
				if state.Plan != nil {
					planID = state.Plan.Hash
					return nil
				}
				snapshot, err := l.sidecar.verifiedIRStageSnapshotTx(
					ctx,
					q,
					tenantID,
				)
				if err != nil {
					return err
				}
				if snapshot.Head.LastAuditSeq > covered {
					return fmt.Errorf(
						"audit: IR sidecar sequence %d exceeds verified WORM coverage %d",
						snapshot.Head.LastAuditSeq,
						covered,
					)
				}
				currentProvider, err := l.sidecar.keys.WrapProviderForTenant(
					ctx,
					tenantID,
				)
				if err != nil &&
					(snapshot.Head.RecordCount != 0 ||
						!errors.Is(err, ErrIRKeyUnavailable)) {
					return fmt.Errorf(
						"audit: resolve current tenant IR wrapping key: %w",
						err,
					)
				}
				if currentProvider != nil {
					currentKeyID := currentProvider.KeyID()
					if disposable, ok := currentProvider.(interface{ Destroy() }); ok {
						disposable.Destroy()
					}
					snapshot.KeyIDs = append(snapshot.KeyIDs, currentKeyID)
				}
				sort.Strings(snapshot.KeyIDs)
				snapshot.KeyIDs = compactSortedStrings(snapshot.KeyIDs)
				manifest, err := l.destroyer.Inventory(
					ctx,
					tenantID,
					snapshot.KeyIDs,
				)
				if err != nil {
					return fmt.Errorf("audit: inventory tenant IR key artifacts: %w", err)
				}
				if manifest.Domain != irKeyArtifactDestroyDomain ||
					manifest.Subject != tenantID {
					return errors.New("audit: IR key artifact manifest has the wrong domain")
				}
				if snapshot.Head.RecordCount > 0 &&
					len(manifest.Artifacts) == 0 {
					return errors.New(
						"audit: non-empty IR sidecar has no destroyable key artifact",
					)
				}
				manifestHash, err := crypto.HashKeyArtifactManifest(manifest)
				if err != nil {
					return fmt.Errorf("audit: validate IR key artifact manifest: %w", err)
				}
				event, err := providerAppendLocked(
					ctx,
					q,
					actor,
					ActionIRKeyDestroyIntent,
					tenantID,
					map[string]any{
						"tenant_id":         tenantID,
						"covered_seq":       covered,
						"ir_record_count":   snapshot.Head.RecordCount,
						"ir_last_audit_seq": snapshot.Head.LastAuditSeq,
						"manifest_hash":     manifestHash,
					},
				)
				if err != nil {
					return fmt.Errorf("audit: append IR key destruction intent: %w", err)
				}
				record := irKeyShredRecord{
					TenantID:         tenantID,
					ChainPos:         1,
					Kind:             "plan",
					CoveredSeq:       covered,
					IRRecordCount:    snapshot.Head.RecordCount,
					IRLastAuditSeq:   snapshot.Head.LastAuditSeq,
					IRLastHash:       snapshot.Head.LastHash,
					ArtifactManifest: manifest,
					ActorHash:        hashIRKeyShredActor(actor),
					EventRef:         event.Hash,
				}
				if err := l.sidecar.appendIRKeyShredRecordTx(
					ctx,
					q,
					&record,
				); err != nil {
					return err
				}
				planID = record.Hash
				return nil
			})
		},
	)
	if err != nil {
		return "", err
	}
	return planID, nil
}

// Execute destroys exactly the signed manifest and appends the tombstone and
// completion audit event atomically. A crash after filesystem/KMS destruction
// leaves the plan pending; retry verifies absence and completes the tombstone.
func (l *IRKeyLifecycle) Execute(
	ctx context.Context,
	tenantID, actor, planID string,
) error {
	if err := validateIRKeyShredCaller(tenantID, actor); err != nil {
		return err
	}
	if l == nil || l.sidecar == nil || l.destroyer == nil {
		return errors.New("audit: IR key destruction capability is not mounted")
	}
	if !irLowerHex64.MatchString(planID) {
		return errors.New("audit: IR key destruction plan id is invalid")
	}
	covered, err := l.sidecar.CoverageWatermark(
		ctx,
		l.worm.objects,
		l.worm.readVerifiedWORMSegment,
	)
	if err != nil {
		return fmt.Errorf(
			"audit: reverify IR coverage before key destruction: %w",
			err,
		)
	}

	var manifest crypto.KeyArtifactManifest
	alreadyDestroyed := false
	err = tenancy.InProvider(
		ctx,
		l.sidecar.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			return withIRTenantRoute(ctx, q, tenantID, func() error {
				if err := lockIRTenant(ctx, q, tenantID); err != nil {
					return err
				}
				state, err := l.sidecar.verifyIRKeyShredStateTx(
					ctx,
					q,
					tenantID,
					true,
				)
				if err != nil {
					return err
				}
				if state.Plan == nil || state.Plan.Hash != planID {
					return errors.New("audit: IR key destruction plan does not match")
				}
				snapshot, err := l.sidecar.verifiedIRStageSnapshotTx(
					ctx,
					q,
					tenantID,
				)
				if err != nil {
					return err
				}
				if covered < state.Plan.IRLastAuditSeq ||
					snapshot.Head.RecordCount != state.Plan.IRRecordCount ||
					snapshot.Head.LastAuditSeq != state.Plan.IRLastAuditSeq ||
					snapshot.Head.LastHash != state.Plan.IRLastHash {
					return errors.New(
						"audit: current IR sidecar/coverage differs from the signed destruction plan",
					)
				}
				manifest = state.Plan.ArtifactManifest
				if state.Tombstone != nil {
					if state.Tombstone.PlanRef != planID {
						return errors.New("audit: IR key tombstone references another plan")
					}
					alreadyDestroyed = true
				}
				return nil
			})
		},
	)
	if err != nil {
		return err
	}
	if alreadyDestroyed {
		return nil
	}

	receipt, err := l.destroyer.Destroy(ctx, manifest)
	if err != nil {
		return fmt.Errorf("audit: destroy tenant IR key artifacts: %w", err)
	}
	if err := l.destroyer.VerifyDestroyed(ctx, manifest); err != nil {
		return fmt.Errorf("audit: verify tenant IR key artifacts destroyed: %w", err)
	}
	manifestHash, err := crypto.HashKeyArtifactManifest(manifest)
	if err != nil {
		return err
	}
	if receipt.ManifestHash != manifestHash ||
		receipt.Destroyed != len(manifest.Artifacts) {
		return errors.New("audit: IR key destruction receipt does not match its plan")
	}
	destroyReceiptHash, err := hashCanonical(struct {
		Domain       string `json:"domain"`
		TenantID     string `json:"tenant_id"`
		PlanRef      string `json:"plan_ref"`
		ManifestHash string `json:"manifest_hash"`
		Destroyed    int    `json:"destroyed"`
	}{
		Domain:       irKeyShredReceiptDomain,
		TenantID:     tenantID,
		PlanRef:      planID,
		ManifestHash: receipt.ManifestHash,
		Destroyed:    receipt.Destroyed,
	})
	if err != nil {
		return err
	}

	return tenancy.InProvider(
		ctx,
		l.sidecar.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			if err := lockProviderStream(ctx, q); err != nil {
				return fmt.Errorf("audit: lock provider stream for IR key tombstone: %w", err)
			}
			return withIRTenantRoute(ctx, q, tenantID, func() error {
				if err := lockIRTenant(ctx, q, tenantID); err != nil {
					return err
				}
				state, err := l.sidecar.verifyIRKeyShredStateTx(
					ctx,
					q,
					tenantID,
					true,
				)
				if err != nil {
					return err
				}
				if state.Plan == nil || state.Plan.Hash != planID {
					return errors.New("audit: IR key destruction plan changed")
				}
				if state.Tombstone != nil {
					if state.Tombstone.PlanRef != planID {
						return errors.New("audit: IR key tombstone references another plan")
					}
					return nil
				}
				if got, err := crypto.HashKeyArtifactManifest(
					state.Plan.ArtifactManifest,
				); err != nil || got != manifestHash {
					return errors.New("audit: IR key destruction manifest changed")
				}
				event, err := providerAppendLocked(
					ctx,
					q,
					actor,
					ActionIRKeyDestroyCompleted,
					tenantID,
					map[string]any{
						"tenant_id":       tenantID,
						"plan_ref":        planID,
						"manifest_hash":   manifestHash,
						"destroyed_count": receipt.Destroyed,
						"receipt_hash":    destroyReceiptHash,
					},
				)
				if err != nil {
					return fmt.Errorf("audit: append IR key destruction completion: %w", err)
				}
				plan := state.Plan
				tombstone := irKeyShredRecord{
					TenantID:           tenantID,
					ChainPos:           2,
					Kind:               "tombstone",
					PlanRef:            planID,
					CoveredSeq:         plan.CoveredSeq,
					IRRecordCount:      plan.IRRecordCount,
					IRLastAuditSeq:     plan.IRLastAuditSeq,
					IRLastHash:         plan.IRLastHash,
					ArtifactManifest:   manifest,
					ActorHash:          hashIRKeyShredActor(actor),
					EventRef:           event.Hash,
					DestroyedCount:     int64(receipt.Destroyed),
					DestroyReceiptHash: destroyReceiptHash,
					PrevHash:           planID,
				}
				return l.sidecar.appendIRKeyShredRecordTx(
					ctx,
					q,
					&tombstone,
				)
			})
		},
	)
}

// RecordFailure appends a separately audited, bounded failure class. It never
// stores raw dependency errors, key paths, or key material.
func (l *IRKeyLifecycle) RecordFailure(
	ctx context.Context,
	tenantID, actor, planID, failure string,
) error {
	if err := validateIRKeyShredCaller(tenantID, actor); err != nil {
		return err
	}
	return l.recordFailure(ctx, tenantID, actor, planID, failure)
}

func (l *IRKeyLifecycle) recordFailure(
	ctx context.Context,
	tenantID, actor, planID, failure string,
) error {
	switch failure {
	case "plan_failed":
		if planID != "" {
			return errors.New("audit: failed IR plan receipt has an unexpected plan id")
		}
	case "store_erasure_incomplete", "crypto_shred_failed":
		if !irLowerHex64.MatchString(planID) {
			return errors.New("audit: failed IR destruction receipt has an invalid plan id")
		}
	default:
		return errors.New("audit: IR key destruction failure class is invalid")
	}
	if l == nil || l.sidecar == nil || l.sidecar.pool == nil {
		return errors.New("audit: IR key destruction audit runtime is unavailable")
	}
	_, err := ProviderAppend(
		ctx,
		l.sidecar.pool,
		actor,
		ActionIRKeyDestroyFailed,
		tenantID,
		map[string]any{
			"tenant_id":     tenantID,
			"plan_ref":      planID,
			"failure_class": failure,
		},
	)
	if err != nil {
		return fmt.Errorf("audit: append IR key destruction failure: %w", err)
	}
	return nil
}

// VerifyIRKeyShredLedger checks every retained per-tenant plan/tombstone chain
// visible through the tenant-first provider route. Tenant registry tombstones
// survive deletion, so completed proof remains reachable at startup.
func (l *IRKeyLifecycle) VerifyIRKeyShredLedger(ctx context.Context) error {
	if l == nil || l.sidecar == nil || l.sidecar.pool == nil {
		return errors.New("audit: IR key destruction ledger is unavailable")
	}
	var tenantIDs []string
	if err := tenancy.InProvider(
		ctx,
		l.sidecar.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			rows, err := q.Query(ctx, `SELECT id::text FROM public.tenants ORDER BY id`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var tenantID string
				if err := rows.Scan(&tenantID); err != nil {
					return err
				}
				tenantIDs = append(tenantIDs, tenantID)
			}
			return rows.Err()
		},
	); err != nil {
		return fmt.Errorf("audit: enumerate IR key destruction ledgers: %w", err)
	}
	ledgerRefs := make(map[string]string)
	for _, tenantID := range tenantIDs {
		var state irKeyShredState
		err := tenancy.InProvider(
			ctx,
			l.sidecar.pool,
			func(ctx context.Context, q tenancy.Querier) error {
				return withIRTenantRoute(ctx, q, tenantID, func() error {
					var err error
					state, err = l.sidecar.verifyIRKeyShredStateTx(
						ctx,
						q,
						tenantID,
						false,
					)
					return err
				})
			},
		)
		if err != nil {
			return fmt.Errorf(
				"audit: verify tenant %s IR key destruction ledger: %w",
				tenantID,
				err,
			)
		}
		if state.Plan != nil {
			ledgerRefs[state.Plan.EventRef] = ActionIRKeyDestroyIntent
		}
		if state.Tombstone != nil {
			ledgerRefs[state.Tombstone.EventRef] = ActionIRKeyDestroyCompleted
		}
	}
	auditRefs, err := l.readIRKeyShredAuditRefs(ctx)
	if err != nil {
		return err
	}
	for eventRef, action := range auditRefs {
		if ledgerRefs[eventRef] != action {
			return fmt.Errorf(
				"audit: %s event %s lacks its signed IR key destruction record",
				action,
				eventRef,
			)
		}
	}
	for eventRef, action := range ledgerRefs {
		if auditRefs[eventRef] != action {
			return fmt.Errorf(
				"audit: signed IR key destruction record %s lacks its %s event",
				eventRef,
				action,
			)
		}
	}
	return nil
}

func (l *IRKeyLifecycle) readIRKeyShredAuditRefs(
	ctx context.Context,
) (map[string]string, error) {
	refs := make(map[string]string)
	add := func(eventRef, action string) error {
		if !irLowerHex64.MatchString(eventRef) {
			return errors.New("audit: IR key destruction audit reference is malformed")
		}
		switch action {
		case ActionIRKeyDestroyIntent, ActionIRKeyDestroyCompleted:
		default:
			return errors.New("audit: IR key destruction audit action is invalid")
		}
		if previous, exists := refs[eventRef]; exists && previous != action {
			return errors.New("audit: IR key destruction audit reference is ambiguous")
		}
		refs[eventRef] = action
		return nil
	}
	if err := tenancy.InProvider(
		ctx,
		l.sidecar.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			rows, err := q.Query(
				ctx,
				`SELECT hash, action
				   FROM public.provider_audit_events
				  WHERE action = $1 OR action = $2`,
				ActionIRKeyDestroyIntent,
				ActionIRKeyDestroyCompleted,
			)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var eventRef, action string
				if err := rows.Scan(&eventRef, &action); err != nil {
					return err
				}
				if err := add(eventRef, action); err != nil {
					return err
				}
			}
			return rows.Err()
		},
	); err != nil {
		return nil, fmt.Errorf(
			"audit: read live IR key destruction audit references: %w",
			err,
		)
	}
	keys, err := l.worm.objects.ListLimited(
		ctx,
		wormPrefix+"segment-",
		maxWORMSegmentArtifacts,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"audit: list WORM segments for IR key destruction verification: %w",
			err,
		)
	}
	segmentKeys, incompleteTail, err := inventoryWORMSegmentArtifacts(
		keys,
		false,
	)
	if err != nil {
		return nil, err
	}
	if incompleteTail != "" {
		return nil, errors.New(
			"audit: incomplete WORM tail during IR key destruction verification",
		)
	}
	for _, key := range segmentKeys {
		verified, err := l.worm.readVerifiedWORMSegment(ctx, key, "")
		if err != nil {
			return nil, err
		}
		for _, event := range verified.segment.Events {
			switch event.Action {
			case ActionIRKeyDestroyIntent, ActionIRKeyDestroyCompleted:
				if err := add(event.Hash, event.Action); err != nil {
					return nil, err
				}
			}
		}
	}
	return refs, nil
}

func (s *IRStagePG) assertIRKeyActiveTx(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
) error {
	state, err := s.verifyIRKeyShredStateTx(ctx, q, tenantID, false)
	if err != nil {
		return fmt.Errorf("audit: verify IR key destruction ledger: %w", err)
	}
	if state.Plan != nil || state.Tombstone != nil {
		return ErrIRKeyUnavailable
	}
	return nil
}

func (s *IRStagePG) verifiedIRStageSnapshotTx(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
) (irStageSnapshot, error) {
	head, exists, err := s.readOptionalHead(ctx, q, tenantID, true)
	if err != nil {
		return irStageSnapshot{}, err
	}
	rows, err := q.Query(
		ctx,
		`SELECT audit_seq, chain_pos, event_ref, key_id, wrapped_dek,
		        ciphertext, prev_hash, hash, signature
		   FROM ir_attribution_records
		  WHERE tenant_id = $1::uuid
		  ORDER BY chain_pos`,
		tenantID,
	)
	if err != nil {
		return irStageSnapshot{}, fmt.Errorf("audit: read IR attribution chain: %w", err)
	}
	defer rows.Close()
	keySet := make(map[string]struct{})
	var count, lastSeq int64
	lastHash := ""
	for rows.Next() {
		var record irStoredStage
		if err := rows.Scan(
			&record.AuditSeq,
			&record.ChainPos,
			&record.EventRef,
			&record.KeyID,
			&record.WrappedDEK,
			&record.Ciphertext,
			&record.PrevHash,
			&record.Hash,
			&record.Signature,
		); err != nil {
			return irStageSnapshot{}, err
		}
		count++
		if record.ChainPos != count || record.AuditSeq <= lastSeq ||
			record.PrevHash != lastHash {
			return irStageSnapshot{}, fmt.Errorf(
				"audit: IR attribution chain discontinuity at position %d",
				count,
			)
		}
		if err := s.verifyIRStageRecord(tenantID, record); err != nil {
			return irStageSnapshot{}, err
		}
		keySet[record.KeyID] = struct{}{}
		lastSeq, lastHash = record.AuditSeq, record.Hash
	}
	if err := rows.Err(); err != nil {
		return irStageSnapshot{}, err
	}
	if !exists {
		if count != 0 {
			return irStageSnapshot{}, errors.New("audit: IR attribution head is missing")
		}
		head = irStageHead{}
	} else {
		if err := s.verifyHead(tenantID, head); err != nil {
			return irStageSnapshot{}, err
		}
		if head.RecordCount != count ||
			head.LastAuditSeq != lastSeq ||
			head.LastHash != lastHash {
			return irStageSnapshot{}, errors.New(
				"audit: IR attribution head does not match retained chain",
			)
		}
	}
	keyIDs := make([]string, 0, len(keySet))
	for keyID := range keySet {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	return irStageSnapshot{Head: head, KeyIDs: keyIDs}, nil
}

func (s *IRStagePG) verifyIRKeyShredStateTx(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	forUpdate bool,
) (irKeyShredState, error) {
	head, headExists, err := s.readIRKeyShredHeadTx(
		ctx,
		q,
		tenantID,
		forUpdate,
	)
	if err != nil {
		return irKeyShredState{}, err
	}
	rows, err := q.Query(
		ctx,
		`SELECT chain_pos, kind, plan_ref, covered_seq, ir_record_count,
		        ir_last_audit_seq, ir_last_hash, artifact_manifest, actor_hash,
		        event_ref, destroyed_count, destroy_receipt_hash, prev_hash,
		        hash, signature
		   FROM public.ir_key_shred_records
		  WHERE tenant_id = $1::uuid
		  ORDER BY chain_pos`,
		tenantID,
	)
	if err != nil {
		return irKeyShredState{}, fmt.Errorf("audit: read IR key destruction ledger: %w", err)
	}
	defer rows.Close()
	state := irKeyShredState{}
	lastHash := ""
	var count int64
	for rows.Next() {
		var record irKeyShredRecord
		var manifestRaw []byte
		record.TenantID = tenantID
		if err := rows.Scan(
			&record.ChainPos,
			&record.Kind,
			&record.PlanRef,
			&record.CoveredSeq,
			&record.IRRecordCount,
			&record.IRLastAuditSeq,
			&record.IRLastHash,
			&manifestRaw,
			&record.ActorHash,
			&record.EventRef,
			&record.DestroyedCount,
			&record.DestroyReceiptHash,
			&record.PrevHash,
			&record.Hash,
			&record.Signature,
		); err != nil {
			return irKeyShredState{}, err
		}
		if err := json.Unmarshal(
			manifestRaw,
			&record.ArtifactManifest,
		); err != nil {
			return irKeyShredState{}, errors.New(
				"audit: IR key destruction manifest is invalid",
			)
		}
		count++
		if record.ChainPos != count || record.PrevHash != lastHash {
			return irKeyShredState{}, errors.New(
				"audit: IR key destruction ledger is discontinuous",
			)
		}
		if err := s.verifyIRKeyShredRecord(record); err != nil {
			return irKeyShredState{}, err
		}
		switch {
		case count == 1 && record.Kind == "plan" &&
			record.PlanRef == "" && record.DestroyedCount == 0 &&
			record.DestroyReceiptHash == "":
			recordCopy := record
			state.Plan = &recordCopy
		case count == 2 && record.Kind == "tombstone" &&
			state.Plan != nil && record.PlanRef == state.Plan.Hash &&
			record.DestroyedCount == int64(len(record.ArtifactManifest.Artifacts)) &&
			irLowerHex64.MatchString(record.DestroyReceiptHash):
			planManifestHash, planErr := crypto.HashKeyArtifactManifest(
				state.Plan.ArtifactManifest,
			)
			recordManifestHash, recordErr := crypto.HashKeyArtifactManifest(
				record.ArtifactManifest,
			)
			if planErr != nil || recordErr != nil ||
				planManifestHash != recordManifestHash ||
				record.CoveredSeq != state.Plan.CoveredSeq ||
				record.IRRecordCount != state.Plan.IRRecordCount ||
				record.IRLastAuditSeq != state.Plan.IRLastAuditSeq ||
				record.IRLastHash != state.Plan.IRLastHash {
				return irKeyShredState{}, errors.New(
					"audit: IR key tombstone differs from its signed plan",
				)
			}
			recordCopy := record
			state.Tombstone = &recordCopy
		default:
			return irKeyShredState{}, errors.New(
				"audit: IR key destruction ledger has an invalid state",
			)
		}
		lastHash = record.Hash
	}
	if err := rows.Err(); err != nil {
		return irKeyShredState{}, err
	}
	if !headExists {
		if count != 0 {
			return irKeyShredState{}, errors.New(
				"audit: IR key destruction head is missing",
			)
		}
		return state, nil
	}
	if err := s.verifyIRKeyShredHead(tenantID, head); err != nil {
		return irKeyShredState{}, err
	}
	if head.RecordCount != count || head.LastHash != lastHash {
		return irKeyShredState{}, errors.New(
			"audit: IR key destruction head does not match its ledger",
		)
	}
	return state, nil
}

func (s *IRStagePG) appendIRKeyShredRecordTx(
	ctx context.Context,
	q tenancy.Querier,
	record *irKeyShredRecord,
) error {
	if record == nil {
		return errors.New("audit: IR key destruction record is required")
	}
	if _, err := q.Exec(
		ctx,
		`INSERT INTO public.ir_key_shred_heads (tenant_id)
		 VALUES ($1::uuid)
		 ON CONFLICT (tenant_id) DO NOTHING`,
		record.TenantID,
	); err != nil {
		return fmt.Errorf("audit: initialize IR key destruction head: %w", err)
	}
	head, exists, err := s.readIRKeyShredHeadTx(
		ctx,
		q,
		record.TenantID,
		true,
	)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("audit: IR key destruction head is missing")
	}
	if err := s.verifyIRKeyShredHead(record.TenantID, head); err != nil {
		return err
	}
	if record.ChainPos != head.RecordCount+1 ||
		record.PrevHash != head.LastHash {
		return errors.New("audit: IR key destruction append is not contiguous")
	}
	record.Hash, err = hashCanonical(irKeyShredRecordHash{
		Domain:             irKeyShredRecordDomain,
		TenantID:           record.TenantID,
		ChainPos:           record.ChainPos,
		Kind:               record.Kind,
		PlanRef:            record.PlanRef,
		CoveredSeq:         record.CoveredSeq,
		IRRecordCount:      record.IRRecordCount,
		IRLastAuditSeq:     record.IRLastAuditSeq,
		IRLastHash:         record.IRLastHash,
		ArtifactManifest:   record.ArtifactManifest,
		ActorHash:          record.ActorHash,
		EventRef:           record.EventRef,
		DestroyedCount:     record.DestroyedCount,
		DestroyReceiptHash: record.DestroyReceiptHash,
		PrevHash:           record.PrevHash,
	})
	if err != nil {
		return err
	}
	record.Signature, err = crypto.SignEd25519(
		s.signingKey,
		[]byte(record.Hash),
	)
	if err != nil {
		return fmt.Errorf("audit: sign IR key destruction record: %w", err)
	}
	manifestRaw, err := json.Marshal(record.ArtifactManifest)
	if err != nil {
		return err
	}
	if _, err := q.Exec(
		ctx,
		`INSERT INTO public.ir_key_shred_records
		    (tenant_id, chain_pos, kind, plan_ref, covered_seq,
		     ir_record_count, ir_last_audit_seq, ir_last_hash,
		     artifact_manifest, actor_hash, event_ref, destroyed_count,
		     destroy_receipt_hash, prev_hash, hash, signature)
		 VALUES
		    ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10,
		     $11, $12, $13, $14, $15, $16)`,
		record.TenantID,
		record.ChainPos,
		record.Kind,
		record.PlanRef,
		record.CoveredSeq,
		record.IRRecordCount,
		record.IRLastAuditSeq,
		record.IRLastHash,
		string(manifestRaw),
		record.ActorHash,
		record.EventRef,
		record.DestroyedCount,
		record.DestroyReceiptHash,
		record.PrevHash,
		record.Hash,
		record.Signature,
	); err != nil {
		return fmt.Errorf("audit: append IR key destruction record: %w", err)
	}
	next := irKeyShredHead{
		RecordCount: record.ChainPos,
		LastHash:    record.Hash,
	}
	next.Signature, err = s.signIRKeyShredHead(record.TenantID, next)
	if err != nil {
		return err
	}
	tag, err := q.Exec(
		ctx,
		`UPDATE public.ir_key_shred_heads
		    SET record_count = $2, last_hash = $3,
		        head_signature = $4, updated_at = now()
		  WHERE tenant_id = $1::uuid
		    AND record_count = $5
		    AND last_hash = $6`,
		record.TenantID,
		next.RecordCount,
		next.LastHash,
		next.Signature,
		head.RecordCount,
		head.LastHash,
	)
	if err != nil {
		return fmt.Errorf("audit: advance IR key destruction head: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("audit: IR key destruction head changed concurrently")
	}
	return nil
}

func (s *IRStagePG) verifyIRKeyShredRecord(record irKeyShredRecord) error {
	if record.ArtifactManifest.Domain != irKeyArtifactDestroyDomain ||
		record.ArtifactManifest.Subject != record.TenantID ||
		record.CoveredSeq < record.IRLastAuditSeq ||
		!irLowerHex64.MatchString(record.ActorHash) ||
		!irLowerHex64.MatchString(record.EventRef) ||
		(record.PrevHash != "" && !irLowerHex64.MatchString(record.PrevHash)) ||
		!irLowerHex64.MatchString(record.Hash) {
		return errors.New("audit: IR key destruction record is malformed")
	}
	if err := crypto.ValidateKeyArtifactManifest(
		record.ArtifactManifest,
	); err != nil {
		return fmt.Errorf("audit: IR key destruction manifest: %w", err)
	}
	if (record.IRRecordCount == 0 &&
		(record.IRLastAuditSeq != 0 || record.IRLastHash != "")) ||
		(record.IRRecordCount > 0 &&
			(record.IRLastAuditSeq < 1 ||
				!irLowerHex64.MatchString(record.IRLastHash))) {
		return errors.New("audit: IR key destruction sidecar anchor is malformed")
	}
	want, err := hashCanonical(irKeyShredRecordHash{
		Domain:             irKeyShredRecordDomain,
		TenantID:           record.TenantID,
		ChainPos:           record.ChainPos,
		Kind:               record.Kind,
		PlanRef:            record.PlanRef,
		CoveredSeq:         record.CoveredSeq,
		IRRecordCount:      record.IRRecordCount,
		IRLastAuditSeq:     record.IRLastAuditSeq,
		IRLastHash:         record.IRLastHash,
		ArtifactManifest:   record.ArtifactManifest,
		ActorHash:          record.ActorHash,
		EventRef:           record.EventRef,
		DestroyedCount:     record.DestroyedCount,
		DestroyReceiptHash: record.DestroyReceiptHash,
		PrevHash:           record.PrevHash,
	})
	if err != nil || want != record.Hash {
		return errors.New("audit: IR key destruction record hash is invalid")
	}
	ok, err := crypto.VerifyEd25519(
		s.verifyKey,
		[]byte(record.Hash),
		record.Signature,
	)
	if err != nil || !ok {
		return errors.New("audit: IR key destruction record signature is invalid")
	}
	return nil
}

func (s *IRStagePG) readIRKeyShredHeadTx(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	forUpdate bool,
) (irKeyShredHead, bool, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	var head irKeyShredHead
	err := q.QueryRow(
		ctx,
		`SELECT record_count, last_hash, head_signature
		   FROM public.ir_key_shred_heads
		  WHERE tenant_id = $1::uuid`+suffix,
		tenantID,
	).Scan(&head.RecordCount, &head.LastHash, &head.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return irKeyShredHead{}, false, nil
	}
	if err != nil {
		return irKeyShredHead{}, false, fmt.Errorf(
			"audit: read IR key destruction head: %w",
			err,
		)
	}
	return head, true, nil
}

func (s *IRStagePG) signIRKeyShredHead(
	tenantID string,
	head irKeyShredHead,
) ([]byte, error) {
	raw, err := json.Marshal(irKeyShredHeadHash{
		Domain:      irKeyShredHeadDomain,
		TenantID:    tenantID,
		RecordCount: head.RecordCount,
		LastHash:    head.LastHash,
	})
	if err != nil {
		return nil, err
	}
	signature, err := crypto.SignEd25519(s.signingKey, raw)
	if err != nil {
		return nil, fmt.Errorf("audit: sign IR key destruction head: %w", err)
	}
	return signature, nil
}

func (s *IRStagePG) verifyIRKeyShredHead(
	tenantID string,
	head irKeyShredHead,
) error {
	if head.RecordCount == 0 {
		if head.LastHash != "" || len(head.Signature) != 0 {
			return errors.New("audit: empty IR key destruction head is malformed")
		}
		return nil
	}
	if head.RecordCount < 1 || head.RecordCount > 2 ||
		!irLowerHex64.MatchString(head.LastHash) {
		return errors.New("audit: IR key destruction head is malformed")
	}
	raw, err := json.Marshal(irKeyShredHeadHash{
		Domain:      irKeyShredHeadDomain,
		TenantID:    tenantID,
		RecordCount: head.RecordCount,
		LastHash:    head.LastHash,
	})
	if err != nil {
		return err
	}
	ok, err := crypto.VerifyEd25519(s.verifyKey, raw, head.Signature)
	if err != nil || !ok {
		return errors.New("audit: IR key destruction head signature is invalid")
	}
	return nil
}

func lockIRTenant(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
) error {
	if _, err := q.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(
		     hashtextextended('ir-attribution:' || $1::text, 0)
		 )`,
		tenantID,
	); err != nil {
		return fmt.Errorf("audit: lock IR attribution tenant: %w", err)
	}
	return nil
}

func validateIRKeyShredCaller(tenantID, actor string) error {
	if !canonicalIRTenantID.MatchString(tenantID) {
		return errors.New("audit: IR key destruction tenant id is invalid")
	}
	actor = strings.TrimSpace(actor)
	if actor == "" || len(actor) > maxIRIdentityBytes {
		return errors.New("audit: IR key destruction actor is invalid")
	}
	return nil
}

func hashIRKeyShredActor(actor string) string {
	return hex.EncodeToString(crypto.Hash([]byte(strings.TrimSpace(actor))))
}

func compactSortedStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	write := 1
	for _, value := range values[1:] {
		if value == values[write-1] {
			continue
		}
		values[write] = value
		write++
	}
	return values[:write]
}
