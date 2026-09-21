// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	ActionIRPostShredRevealDenied = "provider.breakglass_ir_reveal_denied_post_shred"

	irPostShredRecordDomain = "probectl-ir-post-shred-attempt-record-v1"
	irPostShredHeadDomain   = "probectl-ir-post-shred-attempt-head-v1"
	irPostShredSurface      = "audit.ir.reveal"
	irPostShredOutcome      = "denied-post-shred"
)

type irPostShredRecord struct {
	TenantID         string
	ChainPos         int64
	AttemptAt        time.Time
	Operator         string
	Surface          string
	Outcome          string
	ProviderEventRef string
	PrevHash         string
	Hash             string
	Signature        []byte
}

type irPostShredRecordHash struct {
	Domain           string    `json:"domain"`
	TenantID         string    `json:"target_tenant_id"`
	ChainPos         int64     `json:"chain_pos"`
	AttemptAt        time.Time `json:"attempt_at"`
	Operator         string    `json:"operator"`
	Surface          string    `json:"surface"`
	Outcome          string    `json:"outcome"`
	ProviderEventRef string    `json:"provider_event_ref"`
	PrevHash         string    `json:"prev_hash"`
}

type irPostShredHead struct {
	RecordCount int64
	LastHash    string
	Signature   []byte
}

type irPostShredHeadHash struct {
	Domain      string `json:"domain"`
	TenantID    string `json:"target_tenant_id"`
	RecordCount int64  `json:"record_count"`
	LastHash    string `json:"last_hash"`
}

// RecordIRPostShredRevealAttempt records an authenticated denial after the
// tenant's signed key-shred tombstone exists. It never resolves an IR key and
// never calls AppendIRStageTx. The provider event and signed, non-attributing
// companion either commit together or both roll back.
func (s *IRStagePG) RecordIRPostShredRevealAttempt(
	ctx context.Context,
	tenantID, operator string,
) error {
	if s == nil || s.pool == nil || len(s.signingKey) == 0 {
		return errors.New("audit: post-shred IR attempt ledger is unavailable")
	}
	if !canonicalIRTenantID.MatchString(tenantID) {
		return errors.New("audit: post-shred IR target tenant is invalid")
	}
	operator = strings.TrimSpace(operator)
	if operator == "" || len(operator) > maxIRIdentityBytes {
		return errors.New("audit: post-shred IR operator is invalid")
	}
	return tenancy.InProvider(
		ctx,
		s.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			if err := lockProviderStream(ctx, q); err != nil {
				return fmt.Errorf(
					"audit: lock provider stream for post-shred IR attempt: %w",
					err,
				)
			}
			return withIRTenantRoute(ctx, q, tenantID, func() error {
				if err := lockIRTenant(ctx, q, tenantID); err != nil {
					return err
				}
				shredState, err := s.verifyIRKeyShredStateTx(
					ctx,
					q,
					tenantID,
					true,
				)
				if err != nil {
					return err
				}
				if shredState.Tombstone == nil {
					return errors.New(
						"audit: post-shred IR attempt requires a signed key-destruction tombstone",
					)
				}
				_, err = providerAppendLockedWith(
					ctx,
					q,
					operator,
					ActionIRPostShredRevealDenied,
					tenantID,
					map[string]any{
						"target_tenant_id": tenantID,
						"surface":          irPostShredSurface,
						"outcome":          irPostShredOutcome,
					},
					func(event Event) error {
						return s.appendIRPostShredRecordTx(
							ctx,
							q,
							irPostShredRecord{
								TenantID:         tenantID,
								AttemptAt:        event.CreatedAt,
								Operator:         operator,
								Surface:          irPostShredSurface,
								Outcome:          irPostShredOutcome,
								ProviderEventRef: event.Hash,
							},
						)
					},
				)
				return err
			})
		},
	)
}

// VerifyIRPostShredAttemptLedger verifies every retained signed attempt chain,
// then proves a one-to-one binding to the live or signed-WORM provider event.
func (l *IRKeyLifecycle) VerifyIRPostShredAttemptLedger(
	ctx context.Context,
) error {
	if l == nil || l.sidecar == nil || l.sidecar.pool == nil || l.worm == nil {
		return errors.New("audit: post-shred IR attempt verifier is unavailable")
	}
	if err := ProviderVerify(ctx, l.sidecar.pool); err != nil {
		return fmt.Errorf("audit: verify provider stream for post-shred IR attempts: %w", err)
	}
	tenantIDs, err := l.irPostShredTenantIDs(ctx)
	if err != nil {
		return err
	}
	ledgerRefs := make(map[string]struct{})
	for _, tenantID := range tenantIDs {
		var records []irPostShredRecord
		err := tenancy.InProvider(
			ctx,
			l.sidecar.pool,
			func(ctx context.Context, q tenancy.Querier) error {
				return withIRTenantRoute(ctx, q, tenantID, func() error {
					var err error
					records, err = l.sidecar.verifyIRPostShredStateTx(
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
				"audit: verify tenant %s post-shred IR attempts: %w",
				tenantID,
				err,
			)
		}
		for _, record := range records {
			ledgerRefs[record.ProviderEventRef] = struct{}{}
		}
	}
	auditRefs, err := l.readIRPostShredAuditRefs(ctx)
	if err != nil {
		return err
	}
	for eventRef := range auditRefs {
		if _, ok := ledgerRefs[eventRef]; !ok {
			return fmt.Errorf(
				"audit: post-shred IR denial event %s lacks its signed tombstone",
				eventRef,
			)
		}
	}
	for eventRef := range ledgerRefs {
		if _, ok := auditRefs[eventRef]; !ok {
			return fmt.Errorf(
				"audit: signed post-shred IR tombstone %s lacks its provider event",
				eventRef,
			)
		}
	}
	return nil
}

func (l *IRKeyLifecycle) irPostShredTenantIDs(
	ctx context.Context,
) ([]string, error) {
	var tenantIDs []string
	err := tenancy.InProvider(
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
	)
	if err != nil {
		return nil, fmt.Errorf("audit: enumerate post-shred IR attempt ledgers: %w", err)
	}
	return tenantIDs, nil
}

func (l *IRKeyLifecycle) readIRPostShredAuditRefs(
	ctx context.Context,
) (map[string]struct{}, error) {
	refs := make(map[string]struct{})
	add := func(eventRef string) error {
		if !irLowerHex64.MatchString(eventRef) {
			return errors.New("audit: post-shred IR audit reference is malformed")
		}
		refs[eventRef] = struct{}{}
		return nil
	}
	if err := tenancy.InProvider(
		ctx,
		l.sidecar.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			rows, err := q.Query(
				ctx,
				`SELECT hash
				   FROM public.provider_audit_events
				  WHERE action = $1`,
				ActionIRPostShredRevealDenied,
			)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var eventRef string
				if err := rows.Scan(&eventRef); err != nil {
					return err
				}
				if err := add(eventRef); err != nil {
					return err
				}
			}
			return rows.Err()
		},
	); err != nil {
		return nil, fmt.Errorf("audit: read live post-shred IR audit references: %w", err)
	}
	keys, err := l.worm.objects.ListLimited(
		ctx,
		wormPrefix+"segment-",
		maxWORMSegmentArtifacts,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list WORM segments for post-shred IR verification: %w", err)
	}
	segmentKeys, incompleteTail, err := inventoryWORMSegmentArtifacts(keys, false)
	if err != nil {
		return nil, err
	}
	if incompleteTail != "" {
		return nil, errors.New(
			"audit: incomplete WORM tail during post-shred IR verification",
		)
	}
	for _, key := range segmentKeys {
		verified, err := l.worm.readVerifiedWORMSegment(ctx, key, "")
		if err != nil {
			return nil, err
		}
		for _, event := range verified.segment.Events {
			if event.Action == ActionIRPostShredRevealDenied {
				if err := add(event.Hash); err != nil {
					return nil, err
				}
			}
		}
	}
	return refs, nil
}

func (s *IRStagePG) appendIRPostShredRecordTx(
	ctx context.Context,
	q tenancy.Querier,
	record irPostShredRecord,
) error {
	if _, err := q.Exec(
		ctx,
		`INSERT INTO public.ir_post_shred_attempt_heads (tenant_id)
		 VALUES ($1::uuid)
		 ON CONFLICT (tenant_id) DO NOTHING`,
		record.TenantID,
	); err != nil {
		return fmt.Errorf("audit: initialize post-shred IR attempt head: %w", err)
	}
	head, exists, err := s.readIRPostShredHeadTx(
		ctx,
		q,
		record.TenantID,
		true,
	)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("audit: post-shred IR attempt head is missing")
	}
	if err := s.verifyIRPostShredHead(record.TenantID, head); err != nil {
		return err
	}
	record.ChainPos = head.RecordCount + 1
	record.PrevHash = head.LastHash
	record.Hash, err = hashCanonical(irPostShredRecordHash{
		Domain:           irPostShredRecordDomain,
		TenantID:         record.TenantID,
		ChainPos:         record.ChainPos,
		AttemptAt:        record.AttemptAt,
		Operator:         record.Operator,
		Surface:          record.Surface,
		Outcome:          record.Outcome,
		ProviderEventRef: record.ProviderEventRef,
		PrevHash:         record.PrevHash,
	})
	if err != nil {
		return err
	}
	record.Signature, err = crypto.SignEd25519(
		s.signingKey,
		[]byte(record.Hash),
	)
	if err != nil {
		return fmt.Errorf("audit: sign post-shred IR attempt: %w", err)
	}
	if _, err := q.Exec(
		ctx,
		`INSERT INTO public.ir_post_shred_attempt_records
		    (tenant_id, chain_pos, attempt_at, operator, surface, outcome,
		     provider_event_ref, prev_hash, hash, signature)
		 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		record.TenantID,
		record.ChainPos,
		record.AttemptAt,
		record.Operator,
		record.Surface,
		record.Outcome,
		record.ProviderEventRef,
		record.PrevHash,
		record.Hash,
		record.Signature,
	); err != nil {
		return fmt.Errorf("audit: append post-shred IR attempt: %w", err)
	}
	next := irPostShredHead{
		RecordCount: record.ChainPos,
		LastHash:    record.Hash,
	}
	next.Signature, err = s.signIRPostShredHead(record.TenantID, next)
	if err != nil {
		return err
	}
	tag, err := q.Exec(
		ctx,
		`UPDATE public.ir_post_shred_attempt_heads
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
		return fmt.Errorf("audit: advance post-shred IR attempt head: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("audit: post-shred IR attempt head changed concurrently")
	}
	return nil
}

func (s *IRStagePG) verifyIRPostShredStateTx(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	forUpdate bool,
) ([]irPostShredRecord, error) {
	head, headExists, err := s.readIRPostShredHeadTx(
		ctx,
		q,
		tenantID,
		forUpdate,
	)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(
		ctx,
		`SELECT chain_pos, attempt_at, operator, surface, outcome,
		        provider_event_ref, prev_hash, hash, signature
		   FROM public.ir_post_shred_attempt_records
		  WHERE tenant_id = $1::uuid
		  ORDER BY chain_pos`,
		tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: read post-shred IR attempts: %w", err)
	}
	defer rows.Close()
	var records []irPostShredRecord
	lastHash := ""
	for rows.Next() {
		record := irPostShredRecord{TenantID: tenantID}
		if err := rows.Scan(
			&record.ChainPos,
			&record.AttemptAt,
			&record.Operator,
			&record.Surface,
			&record.Outcome,
			&record.ProviderEventRef,
			&record.PrevHash,
			&record.Hash,
			&record.Signature,
		); err != nil {
			return nil, err
		}
		if record.ChainPos != int64(len(records))+1 ||
			record.PrevHash != lastHash {
			return nil, errors.New(
				"audit: post-shred IR attempt ledger is discontinuous",
			)
		}
		if err := s.verifyIRPostShredRecord(record); err != nil {
			return nil, err
		}
		records = append(records, record)
		lastHash = record.Hash
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !headExists {
		if len(records) != 0 {
			return nil, errors.New("audit: post-shred IR attempt head is missing")
		}
		return nil, nil
	}
	if err := s.verifyIRPostShredHead(tenantID, head); err != nil {
		return nil, err
	}
	if head.RecordCount != int64(len(records)) || head.LastHash != lastHash {
		return nil, errors.New(
			"audit: post-shred IR attempt head does not match its ledger",
		)
	}
	return records, nil
}

func (s *IRStagePG) readIRPostShredHeadTx(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	forUpdate bool,
) (irPostShredHead, bool, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	var head irPostShredHead
	err := q.QueryRow(
		ctx,
		`SELECT record_count, last_hash, head_signature
		   FROM public.ir_post_shred_attempt_heads
		  WHERE tenant_id = $1::uuid`+suffix,
		tenantID,
	).Scan(&head.RecordCount, &head.LastHash, &head.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return irPostShredHead{}, false, nil
	}
	if err != nil {
		return irPostShredHead{}, false, fmt.Errorf(
			"audit: read post-shred IR attempt head: %w",
			err,
		)
	}
	return head, true, nil
}

func (s *IRStagePG) verifyIRPostShredRecord(
	record irPostShredRecord,
) error {
	if !canonicalIRTenantID.MatchString(record.TenantID) ||
		record.ChainPos < 1 ||
		record.AttemptAt.IsZero() ||
		strings.TrimSpace(record.Operator) == "" ||
		len(record.Operator) > maxIRIdentityBytes ||
		record.Surface != irPostShredSurface ||
		record.Outcome != irPostShredOutcome ||
		!irLowerHex64.MatchString(record.ProviderEventRef) ||
		(record.PrevHash != "" && !irLowerHex64.MatchString(record.PrevHash)) ||
		!irLowerHex64.MatchString(record.Hash) {
		return errors.New("audit: post-shred IR attempt is malformed")
	}
	want, err := hashCanonical(irPostShredRecordHash{
		Domain:           irPostShredRecordDomain,
		TenantID:         record.TenantID,
		ChainPos:         record.ChainPos,
		AttemptAt:        record.AttemptAt,
		Operator:         record.Operator,
		Surface:          record.Surface,
		Outcome:          record.Outcome,
		ProviderEventRef: record.ProviderEventRef,
		PrevHash:         record.PrevHash,
	})
	if err != nil || want != record.Hash {
		return errors.New("audit: post-shred IR attempt hash is invalid")
	}
	ok, err := crypto.VerifyEd25519(
		s.verifyKey,
		[]byte(record.Hash),
		record.Signature,
	)
	if err != nil || !ok {
		return errors.New("audit: post-shred IR attempt signature is invalid")
	}
	return nil
}

func (s *IRStagePG) signIRPostShredHead(
	tenantID string,
	head irPostShredHead,
) ([]byte, error) {
	raw, err := json.Marshal(irPostShredHeadHash{
		Domain:      irPostShredHeadDomain,
		TenantID:    tenantID,
		RecordCount: head.RecordCount,
		LastHash:    head.LastHash,
	})
	if err != nil {
		return nil, err
	}
	signature, err := crypto.SignEd25519(s.signingKey, raw)
	if err != nil {
		return nil, fmt.Errorf("audit: sign post-shred IR attempt head: %w", err)
	}
	return signature, nil
}

func (s *IRStagePG) verifyIRPostShredHead(
	tenantID string,
	head irPostShredHead,
) error {
	if head.RecordCount == 0 {
		if head.LastHash != "" || len(head.Signature) != 0 {
			return errors.New("audit: empty post-shred IR attempt head is malformed")
		}
		return nil
	}
	if head.RecordCount < 1 || !irLowerHex64.MatchString(head.LastHash) {
		return errors.New("audit: post-shred IR attempt head is malformed")
	}
	raw, err := json.Marshal(irPostShredHeadHash{
		Domain:      irPostShredHeadDomain,
		TenantID:    tenantID,
		RecordCount: head.RecordCount,
		LastHash:    head.LastHash,
	})
	if err != nil {
		return err
	}
	ok, err := crypto.VerifyEd25519(s.verifyKey, raw, head.Signature)
	if err != nil || !ok {
		return errors.New("audit: post-shred IR attempt head signature is invalid")
	}
	return nil
}
