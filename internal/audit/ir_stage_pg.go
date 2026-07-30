// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// IRStagePG persists the append-time inner envelope. It deliberately has no
// Open method: routine operation owns public wrapping capability only.
type IRStagePG struct {
	keys       IRWrapKeyResolver
	signingKey []byte
	verifyKey  []byte
}

// NewIRStagePG creates the local encrypted staging writer and verifier.
func NewIRStagePG(
	keys IRWrapKeyResolver,
	signingPrivatePEM, signingPublicPEM []byte,
) (*IRStagePG, error) {
	if keys == nil {
		return nil, errors.New("audit: IR wrapping-key resolver is required")
	}
	if len(signingPrivatePEM) == 0 || len(signingPublicPEM) == 0 {
		return nil, errors.New("audit: IR chain requires a persisted signing key")
	}
	derived, err := crypto.PublicPEMFromPrivate(signingPrivatePEM)
	if err != nil {
		return nil, fmt.Errorf("audit: IR signing key: %w", err)
	}
	if !bytes.Equal(derived, signingPublicPEM) {
		return nil, errors.New("audit: IR signing public/private keys do not match")
	}
	return &IRStagePG{
		keys:       keys,
		signingKey: append([]byte(nil), signingPrivatePEM...),
		verifyKey:  append([]byte(nil), signingPublicPEM...),
	}, nil
}

type irStageRecordHash struct {
	Domain     string `json:"domain"`
	TenantID   string `json:"tenant_id"`
	AuditSeq   int64  `json:"audit_seq"`
	ChainPos   int64  `json:"chain_pos"`
	EventRef   string `json:"event_ref"`
	KeyID      string `json:"key_id"`
	WrappedDEK []byte `json:"wrapped_dek"`
	Ciphertext []byte `json:"ciphertext"`
	PrevHash   string `json:"prev_hash"`
}

type irStageHeadHash struct {
	Domain       string `json:"domain"`
	TenantID     string `json:"tenant_id"`
	RecordCount  int64  `json:"record_count"`
	LastAuditSeq int64  `json:"last_audit_seq"`
	LastHash     string `json:"last_hash"`
}

type irStageHead struct {
	RecordCount  int64
	LastAuditSeq int64
	LastHash     string
	Signature    []byte
}

type irStoredStage struct {
	AuditSeq   int64
	ChainPos   int64
	EventRef   string
	KeyID      string
	WrappedDEK []byte
	Ciphertext []byte
	PrevHash   string
	Hash       string
	Signature  []byte
}

// AppendIRStageTx seals and appends one record inside the caller's provider
// transaction. Any error is returned to that transaction and therefore rolls
// back both the protected mutation and its provider audit event.
func (s *IRStagePG) AppendIRStageTx(
	ctx context.Context,
	q tenancy.Querier,
	event Event,
	attribution IRAttribution,
) error {
	if s == nil || s.keys == nil {
		return errors.New("audit: encrypted IR sidecar is unavailable")
	}
	if event.Seq < 1 || len(event.Hash) != 64 {
		return errors.New("audit: provider event has an invalid IR anchor")
	}
	if attribution.TenantID == "" ||
		attribution.EventRef != event.Hash ||
		!attribution.TS.Equal(event.CreatedAt) {
		return errors.New("audit: IR attribution is not bound to the provider event")
	}
	plaintext, err := marshalIRAttribution(attribution)
	if err != nil {
		return err
	}
	defer crypto.Zeroize(plaintext)
	provider, err := s.keys.WrapProviderForTenant(ctx, attribution.TenantID)
	if err != nil {
		return fmt.Errorf("audit: resolve tenant IR wrapping key: %w", err)
	}
	sealed, err := crypto.NewEnvelope(provider).Seal(
		ctx,
		plaintext,
		irStageAAD(attribution.TenantID, event.Seq, event.Hash),
	)
	if err != nil {
		return fmt.Errorf("audit: seal IR attribution: %w", err)
	}
	if len(sealed.KeyID) == 0 || len(sealed.KeyID) > 256 ||
		len(sealed.WrappedDEK) == 0 || len(sealed.WrappedDEK) > maxIRWrappedDEKBytes ||
		len(sealed.Ciphertext) == 0 || len(sealed.Ciphertext) > maxIRCiphertextBytes {
		return errors.New("audit: sealed IR attribution exceeds bounded storage shape")
	}

	return withIRTenantRoute(ctx, q, attribution.TenantID, func() error {
		if _, err := q.Exec(
			ctx,
			`SELECT pg_advisory_xact_lock(
			     hashtextextended('ir-attribution:' || $1::text, 0)
			 )`,
			attribution.TenantID,
		); err != nil {
			return fmt.Errorf("audit: lock IR attribution chain: %w", err)
		}
		if _, err := q.Exec(
			ctx,
			`INSERT INTO public.ir_attribution_heads (tenant_id)
			 VALUES ($1::uuid)
			 ON CONFLICT (tenant_id) DO NOTHING`,
			attribution.TenantID,
		); err != nil {
			return fmt.Errorf("audit: initialize IR attribution head: %w", err)
		}
		head, err := s.readHead(ctx, q, attribution.TenantID, true)
		if err != nil {
			return err
		}
		if err := s.verifyHead(attribution.TenantID, head); err != nil {
			return err
		}
		chainPos := head.RecordCount + 1
		hash, err := hashIRStageRecord(irStageRecordHash{
			Domain:     IRKeyDomain,
			TenantID:   attribution.TenantID,
			AuditSeq:   event.Seq,
			ChainPos:   chainPos,
			EventRef:   event.Hash,
			KeyID:      sealed.KeyID,
			WrappedDEK: sealed.WrappedDEK,
			Ciphertext: sealed.Ciphertext,
			PrevHash:   head.LastHash,
		})
		if err != nil {
			return err
		}
		signature, err := crypto.SignEd25519(s.signingKey, []byte(hash))
		if err != nil {
			return fmt.Errorf("audit: sign IR attribution record: %w", err)
		}
		if _, err := q.Exec(
			ctx,
			`INSERT INTO ir_attribution_records
			    (tenant_id, audit_seq, chain_pos, event_ref, key_id,
			     wrapped_dek, ciphertext, prev_hash, hash, signature)
			 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			attribution.TenantID,
			event.Seq,
			chainPos,
			event.Hash,
			sealed.KeyID,
			sealed.WrappedDEK,
			sealed.Ciphertext,
			head.LastHash,
			hash,
			signature,
		); err != nil {
			return fmt.Errorf("audit: insert encrypted IR attribution: %w", err)
		}
		next := irStageHead{
			RecordCount: chainPos, LastAuditSeq: event.Seq, LastHash: hash,
		}
		next.Signature, err = s.signHead(attribution.TenantID, next)
		if err != nil {
			return err
		}
		tag, err := q.Exec(
			ctx,
			`UPDATE public.ir_attribution_heads
			    SET record_count = $2,
			        last_audit_seq = $3,
			        last_hash = $4,
			        head_signature = $5,
			        updated_at = now()
			  WHERE tenant_id = $1::uuid
			    AND record_count = $6`,
			attribution.TenantID,
			next.RecordCount,
			next.LastAuditSeq,
			next.LastHash,
			next.Signature,
			head.RecordCount,
		)
		if err != nil {
			return fmt.Errorf("audit: advance IR attribution head: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return errors.New("audit: IR attribution head changed concurrently")
		}
		return nil
	})
}

// VerifyTenant recomputes one tenant's routed stage chain and signed head.
func (s *IRStagePG) VerifyTenant(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
) error {
	if s == nil || pool == nil {
		return errors.New("audit: IR verification dependencies are unavailable")
	}
	if !canonicalIRTenantID.MatchString(tenantID) {
		return errors.New("audit: IR tenant id is not a canonical UUID")
	}
	return tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		return withIRTenantRoute(ctx, q, tenantID, func() error {
			if _, err := q.Exec(
				ctx,
				`SELECT pg_advisory_xact_lock(
				     hashtextextended('ir-attribution:' || $1::text, 0)
				 )`,
				tenantID,
			); err != nil {
				return err
			}
			head, exists, err := s.readOptionalHead(ctx, q, tenantID, false)
			if err != nil {
				return err
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
				return fmt.Errorf("audit: read IR attribution chain: %w", err)
			}
			defer rows.Close()
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
					return err
				}
				count++
				if record.ChainPos != count || record.AuditSeq <= lastSeq ||
					record.PrevHash != lastHash {
					return fmt.Errorf("audit: IR attribution chain discontinuity at position %d", count)
				}
				want, err := hashIRStageRecord(irStageRecordHash{
					Domain: IRKeyDomain, TenantID: tenantID,
					AuditSeq: record.AuditSeq, ChainPos: record.ChainPos,
					EventRef: record.EventRef, KeyID: record.KeyID,
					WrappedDEK: record.WrappedDEK, Ciphertext: record.Ciphertext,
					PrevHash: record.PrevHash,
				})
				if err != nil {
					return err
				}
				if record.Hash != want {
					return fmt.Errorf("audit: IR attribution hash mismatch at position %d", count)
				}
				ok, err := crypto.VerifyEd25519(s.verifyKey, []byte(record.Hash), record.Signature)
				if err != nil || !ok {
					return fmt.Errorf("audit: IR attribution signature invalid at position %d", count)
				}
				lastSeq, lastHash = record.AuditSeq, record.Hash
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if !exists {
				if count != 0 {
					return errors.New("audit: IR attribution head is missing")
				}
				return nil
			}
			if err := s.verifyHead(tenantID, head); err != nil {
				return err
			}
			if head.RecordCount != count ||
				head.LastAuditSeq != lastSeq ||
				head.LastHash != lastHash {
				return errors.New("audit: IR attribution head does not match retained chain")
			}
			return nil
		})
	})
}

func (s *IRStagePG) readHead(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	forUpdate bool,
) (irStageHead, error) {
	head, exists, err := s.readOptionalHead(ctx, q, tenantID, forUpdate)
	if err != nil {
		return irStageHead{}, err
	}
	if !exists {
		return irStageHead{}, errors.New("audit: IR attribution head is missing")
	}
	return head, nil
}

func (s *IRStagePG) readOptionalHead(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	forUpdate bool,
) (irStageHead, bool, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	var head irStageHead
	err := q.QueryRow(
		ctx,
		`SELECT record_count, last_audit_seq, last_hash, head_signature
		   FROM public.ir_attribution_heads
		  WHERE tenant_id = $1::uuid`+suffix,
		tenantID,
	).Scan(&head.RecordCount, &head.LastAuditSeq, &head.LastHash, &head.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return irStageHead{}, false, nil
	}
	if err != nil {
		return irStageHead{}, false, fmt.Errorf("audit: read IR attribution head: %w", err)
	}
	return head, true, nil
}

func (s *IRStagePG) signHead(tenantID string, head irStageHead) ([]byte, error) {
	raw, err := json.Marshal(irStageHeadHash{
		Domain: IRKeyDomain, TenantID: tenantID,
		RecordCount: head.RecordCount, LastAuditSeq: head.LastAuditSeq,
		LastHash: head.LastHash,
	})
	if err != nil {
		return nil, err
	}
	signature, err := crypto.SignEd25519(s.signingKey, raw)
	if err != nil {
		return nil, fmt.Errorf("audit: sign IR attribution head: %w", err)
	}
	return signature, nil
}

func (s *IRStagePG) verifyHead(tenantID string, head irStageHead) error {
	if head.RecordCount == 0 {
		if head.LastAuditSeq != 0 || head.LastHash != "" || len(head.Signature) != 0 {
			return errors.New("audit: empty IR attribution head is malformed")
		}
		return nil
	}
	if head.LastAuditSeq < 1 || len(head.LastHash) != 64 {
		return errors.New("audit: IR attribution head is malformed")
	}
	raw, err := json.Marshal(irStageHeadHash{
		Domain: IRKeyDomain, TenantID: tenantID,
		RecordCount: head.RecordCount, LastAuditSeq: head.LastAuditSeq,
		LastHash: head.LastHash,
	})
	if err != nil {
		return err
	}
	ok, err := crypto.VerifyEd25519(s.verifyKey, raw, head.Signature)
	if err != nil || !ok {
		return errors.New("audit: IR attribution head signature is invalid")
	}
	return nil
}

func hashIRStageRecord(input irStageRecordHash) (string, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("audit: canonicalize IR attribution record: %w", err)
	}
	return hex.EncodeToString(crypto.Hash(raw)), nil
}

func withIRTenantRoute(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	fn func() error,
) (retErr error) {
	if !canonicalIRTenantID.MatchString(tenantID) {
		return errors.New("audit: IR tenant id is not a canonical UUID")
	}
	var model, previousTenant, previousSearchPath string
	if err := q.QueryRow(
		ctx,
		`SELECT isolation_model::text,
		        COALESCE(current_setting('probectl.tenant_id', true), ''),
		        current_setting('search_path')
		   FROM public.tenants
		  WHERE id = $1::uuid`,
		tenantID,
	).Scan(&model, &previousTenant, &previousSearchPath); err != nil {
		return fmt.Errorf("audit: resolve IR tenant route: %w", err)
	}
	searchPath := "public"
	if model == string(tenancy.IsolationSiloed) {
		searchPath = pgx.Identifier{irSiloSchema(tenantID)}.Sanitize() + ", public"
	}
	if _, err := q.Exec(
		ctx,
		`SELECT set_config('probectl.tenant_id', $1, true),
		        set_config('search_path', $2, true)`,
		tenantID,
		searchPath,
	); err != nil {
		return fmt.Errorf("audit: bind IR tenant route: %w", err)
	}
	defer func() {
		_, restoreErr := q.Exec(
			ctx,
			`SELECT set_config('probectl.tenant_id', $1, true),
			        set_config('search_path', $2, true)`,
			previousTenant,
			previousSearchPath,
		)
		if restoreErr != nil && retErr == nil {
			retErr = fmt.Errorf("audit: restore provider route after IR append: %w", restoreErr)
		}
	}()
	return fn()
}

func irSiloSchema(tenantID string) string {
	return "t_" + strings.ReplaceAll(tenantID, "-", "")
}
