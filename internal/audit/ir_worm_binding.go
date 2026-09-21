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
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	irWORMPrefix               = "worm/audit/ir/"
	irWORMBindingDomain        = "probectl-ir-worm-binding-v1"
	irWORMCompanionDomain      = "probectl-ir-worm-companion-v1"
	irWORMCoverageDomain       = "probectl-ir-worm-coverage-v1"
	irWORMCoverageHeadDomain   = "probectl-ir-worm-coverage-head-v1"
	maxIRWORMCompanionBytes    = 8 << 20
	maxIRWORMCompanionRecords  = MaxExportPageSize
	maxIRWORMCompanionObjects  = maxWORMSegmentArtifacts / 2
	irWORMCompanionContentType = "application/json"
)

var irLowerHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// IRWORMDurability is the narrow seam used by the provider WORM exporter.
// Implementations receive the exact signed WORM bytes, persist the separately
// encrypted companion, then advance a signed continuous coverage watermark.
type IRWORMDurability interface {
	PersistWORMCompanion(
		context.Context,
		objectstore.Store,
		verifiedWORMSegment,
	) error
	VerifyIRStages(context.Context) error
	CoverageWatermark(
		context.Context,
		objectstore.Store,
		irWORMSegmentVerifier,
	) (int64, error)
}

// IRWORMCompanionRecord is the outer envelope for one append-time stage.
// The tenant identifier remains only inside the encrypted attribution and the
// caller-supplied AAD; it is intentionally absent from these global object
// bytes so repeated break-glass events cannot be linked by tenant. Opening it
// requires AAD {tenant_id,audit_seq,worm_segment_hash}; its plaintext is itself
// the encoded inner envelope, so the binder never opens operator attribution.
type IRWORMCompanionRecord struct {
	AuditSeq   int64  `json:"audit_seq"`
	StageHash  string `json:"stage_hash"`
	KeyID      string `json:"key_id"`
	WrappedDEK []byte `json:"wrapped_dek"`
	Ciphertext []byte `json:"ciphertext"`
	Hash       string `json:"hash"`
	Signature  []byte `json:"signature"`
}

// IRWORMCompanion is the canonical, separately signed object adjacent to one
// minimized WORM segment. It contains no cleartext operator, grant, consent,
// reason, outcome, or event target.
type IRWORMCompanion struct {
	FormatVersion   int                     `json:"format_version"`
	Domain          string                  `json:"domain"`
	FromSeq         int64                   `json:"from_seq"`
	ToSeq           int64                   `json:"to_seq"`
	WORMSegmentHash string                  `json:"worm_segment_hash"`
	Records         []IRWORMCompanionRecord `json:"records"`
	PayloadHash     string                  `json:"payload_hash"`
	Signature       []byte                  `json:"signature"`
}

type irWORMCompanionPayload struct {
	FormatVersion   int                     `json:"format_version"`
	Domain          string                  `json:"domain"`
	FromSeq         int64                   `json:"from_seq"`
	ToSeq           int64                   `json:"to_seq"`
	WORMSegmentHash string                  `json:"worm_segment_hash"`
	Records         []IRWORMCompanionRecord `json:"records"`
}

type irWORMRecordHash struct {
	Domain          string `json:"domain"`
	TenantID        string `json:"tenant_id"`
	AuditSeq        int64  `json:"audit_seq"`
	WORMSegmentHash string `json:"worm_segment_hash"`
	StageHash       string `json:"stage_hash"`
	KeyID           string `json:"key_id"`
	WrappedDEK      []byte `json:"wrapped_dek"`
	Ciphertext      []byte `json:"ciphertext"`
}

type irCoverageRecord struct {
	FromSeq          int64
	ToSeq            int64
	WORMSegmentHash  string
	CompanionKey     string
	CompanionHash    string
	ProtectedRecords int64
	PrevHash         string
	Hash             string
	Signature        []byte
}

type irCoverageHash struct {
	Domain           string `json:"domain"`
	FromSeq          int64  `json:"from_seq"`
	ToSeq            int64  `json:"to_seq"`
	WORMSegmentHash  string `json:"worm_segment_hash"`
	CompanionKey     string `json:"companion_key"`
	CompanionHash    string `json:"companion_hash"`
	ProtectedRecords int64  `json:"protected_records"`
	PrevHash         string `json:"prev_hash"`
}

type irCoverageHead struct {
	CoveredSeq    int64
	LastHash      string
	CompanionHash string
	Signature     []byte
}

type irCoverageHeadHash struct {
	Domain        string `json:"domain"`
	CoveredSeq    int64  `json:"covered_seq"`
	LastHash      string `json:"last_hash"`
	CompanionHash string `json:"companion_hash"`
}

func irWORMCompanionKey(fromSeq, toSeq int64) string {
	return fmt.Sprintf(
		"%ssegment-%012d-%012d.ir.json",
		irWORMPrefix,
		fromSeq,
		toSeq,
	)
}

func irWORMStageAAD(tenantID string, auditSeq int64, segmentHash string) []byte {
	raw, _ := json.Marshal(struct {
		Domain          string `json:"domain"`
		TenantID        string `json:"tenant_id"`
		AuditSeq        int64  `json:"audit_seq"`
		WORMSegmentHash string `json:"worm_segment_hash"`
	}{
		Domain: irWORMBindingDomain, TenantID: tenantID,
		AuditSeq: auditSeq, WORMSegmentHash: segmentHash,
	})
	return raw
}

func (c IRWORMCompanion) canonicalPayloadJSON() ([]byte, error) {
	return json.Marshal(irWORMCompanionPayload{
		FormatVersion:   c.FormatVersion,
		Domain:          c.Domain,
		FromSeq:         c.FromSeq,
		ToSeq:           c.ToSeq,
		WORMSegmentHash: c.WORMSegmentHash,
		Records:         c.Records,
	})
}

func (c IRWORMCompanion) canonicalJSON() ([]byte, error) {
	return json.Marshal(c)
}

func hashCanonical(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(crypto.Hash(raw)), nil
}

// PersistWORMCompanion writes or verifies one immutable outer-envelope
// companion and advances coverage only after a read-back verification.
func (s *IRStagePG) PersistWORMCompanion(
	ctx context.Context,
	objects objectstore.Store,
	verified verifiedWORMSegment,
) error {
	if s == nil || s.pool == nil || objects == nil {
		return errors.New("audit: IR WORM durability dependencies are unavailable")
	}
	segment := verified.segment
	segmentRaw := verified.raw
	segmentHash, err := validateIRWORMSegment(segment, segmentRaw)
	if err != nil {
		return err
	}
	if verified.hash != segmentHash {
		return errors.New("audit: verified WORM segment hash changed before IR binding")
	}
	return tenancy.InProvider(
		ctx,
		s.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			// Hold one provider transaction and one advisory transaction lock
			// across object read/write/read-back and SQL finalization. This
			// prevents two singleton failover candidates from overwriting a
			// deterministic object key with different randomized ciphertext.
			if _, err := q.Exec(
				ctx,
				`SELECT pg_advisory_xact_lock(
				     hashtextextended('audit:ir:worm-coverage', 0)
				 )`,
			); err != nil {
				return fmt.Errorf("audit: lock IR WORM coverage: %w", err)
			}
			return s.persistWORMCompanionLocked(
				ctx,
				q,
				objects,
				segment,
				segmentHash,
			)
		},
	)
}

func (s *IRStagePG) persistWORMCompanionLocked(
	ctx context.Context,
	q tenancy.Querier,
	objects objectstore.Store,
	segment WormSegment,
	segmentHash string,
) error {
	key := irWORMCompanionKey(segment.FromSeq, segment.ToSeq)
	existing, err := objects.GetLimited(ctx, key, maxIRWORMCompanionBytes)
	switch {
	case err == nil:
		if existing.ContentType != irWORMCompanionContentType {
			return fmt.Errorf(
				"audit: IR WORM companion %s has content type %q",
				key,
				existing.ContentType,
			)
		}
		companion, err := s.decodeAndVerifyIRWORMCompanion(
			existing.Data,
			segment,
			segmentHash,
		)
		if err != nil {
			return fmt.Errorf("audit: verify existing IR WORM companion: %w", err)
		}
		if err := s.verifyIRWORMCompanionStages(
			ctx,
			q,
			companion,
			segment,
		); err != nil {
			return err
		}
		return s.commitIRWORMCoverageLocked(
			ctx,
			q,
			companion,
			key,
			hex.EncodeToString(crypto.Hash(existing.Data)),
		)
	case !errors.Is(err, objectstore.ErrNotFound):
		return fmt.Errorf("audit: read IR WORM companion %s: %w", key, err)
	}
	covered, err := s.irCoverageRangeExists(
		ctx,
		q,
		segment.FromSeq,
		segment.ToSeq,
	)
	if err != nil {
		return err
	}
	if covered {
		return errors.New(
			"audit: committed IR WORM companion is missing; refusing randomized reconstruction",
		)
	}
	companion, err := s.buildIRWORMCompanion(
		ctx,
		q,
		segment,
		segmentHash,
	)
	if err != nil {
		return err
	}
	raw, err := companion.canonicalJSON()
	if err != nil {
		return fmt.Errorf("audit: canonicalize IR WORM companion: %w", err)
	}
	if len(raw) > maxIRWORMCompanionBytes {
		return fmt.Errorf(
			"audit: IR WORM companion exceeds %d bytes",
			maxIRWORMCompanionBytes,
		)
	}
	if err := objects.Put(
		ctx,
		key,
		irWORMCompanionContentType,
		raw,
	); err != nil {
		return fmt.Errorf("audit: persist IR WORM companion: %w", err)
	}
	readBack, err := objects.GetLimited(ctx, key, maxIRWORMCompanionBytes)
	if err != nil {
		return fmt.Errorf("audit: read back IR WORM companion: %w", err)
	}
	if readBack.ContentType != irWORMCompanionContentType ||
		!bytes.Equal(readBack.Data, raw) {
		return errors.New("audit: persisted IR WORM companion differs on read-back")
	}
	if _, err := s.decodeAndVerifyIRWORMCompanion(
		readBack.Data,
		segment,
		segmentHash,
	); err != nil {
		return fmt.Errorf("audit: verify persisted IR WORM companion: %w", err)
	}
	if err := s.verifyIRWORMCompanionStages(
		ctx,
		q,
		companion,
		segment,
	); err != nil {
		return err
	}
	return s.commitIRWORMCoverageLocked(
		ctx,
		q,
		companion,
		key,
		hex.EncodeToString(crypto.Hash(raw)),
	)
}

func validateIRWORMSegment(segment WormSegment, raw []byte) (string, error) {
	if segment.FormatVersion != 1 ||
		segment.Stream != providerStream ||
		segment.FromSeq < 1 ||
		segment.ToSeq < segment.FromSeq ||
		len(segment.Events) == 0 ||
		len(segment.Events) > MaxExportPageSize ||
		segment.ExportedAt.IsZero() ||
		segment.Events[0].Seq != segment.FromSeq ||
		segment.Events[len(segment.Events)-1].Seq != segment.ToSeq {
		return "", errors.New("audit: invalid verified WORM segment for IR binding")
	}
	for i, event := range segment.Events {
		if event.Seq != segment.FromSeq+int64(i) ||
			!irLowerHex64.MatchString(event.Hash) {
			return "", errors.New("audit: non-contiguous WORM segment for IR binding")
		}
	}
	if len(raw) == 0 || int64(len(raw)) > maxWORMSegmentBytes {
		return "", errors.New("audit: invalid WORM segment bytes for IR binding")
	}
	canonical, err := json.Marshal(segment)
	if err != nil {
		return "", fmt.Errorf("audit: canonicalize WORM segment for IR binding: %w", err)
	}
	if !bytes.Equal(raw, canonical) {
		return "", errors.New("audit: WORM segment for IR binding is not canonical JSON")
	}
	return hex.EncodeToString(crypto.Hash(raw)), nil
}

func classifyIRWORMAction(action string) (bool, error) {
	if isProtectedBreakGlassAction(action) {
		return true, nil
	}
	normalized := strings.ToLower(strings.TrimSpace(action))
	if strings.Contains(normalized, "breakglass") ||
		strings.Contains(normalized, "break_glass") ||
		strings.Contains(normalized, "break-glass") {
		return false, fmt.Errorf(
			"audit: legacy or unknown break-glass action %q cannot receive empty IR coverage",
			action,
		)
	}
	return false, nil
}

func (s *IRStagePG) buildIRWORMCompanion(
	ctx context.Context,
	q tenancy.Querier,
	segment WormSegment,
	segmentHash string,
) (IRWORMCompanion, error) {
	companion := IRWORMCompanion{
		FormatVersion:   1,
		Domain:          irWORMCompanionDomain,
		FromSeq:         segment.FromSeq,
		ToSeq:           segment.ToSeq,
		WORMSegmentHash: segmentHash,
		Records:         []IRWORMCompanionRecord{},
	}
	for _, wormEvent := range segment.Events {
		protected, err := classifyIRWORMAction(wormEvent.Action)
		if err != nil {
			return IRWORMCompanion{}, err
		}
		if !protected {
			continue
		}
		record, err := s.buildIRWORMRecord(
			ctx,
			q,
			wormEvent,
			segmentHash,
		)
		if err != nil {
			return IRWORMCompanion{}, err
		}
		companion.Records = append(companion.Records, record)
	}
	payload, err := companion.canonicalPayloadJSON()
	if err != nil {
		return IRWORMCompanion{}, err
	}
	companion.PayloadHash = hex.EncodeToString(crypto.Hash(payload))
	companion.Signature, err = crypto.SignEd25519(
		s.signingKey,
		[]byte(companion.PayloadHash),
	)
	if err != nil {
		return IRWORMCompanion{}, fmt.Errorf("audit: sign IR WORM companion: %w", err)
	}
	return companion, nil
}

func (s *IRStagePG) buildIRWORMRecord(
	ctx context.Context,
	q tenancy.Querier,
	wormEvent Event,
	segmentHash string,
) (IRWORMCompanionRecord, error) {
	var action, eventHash string
	var data map[string]any
	err := q.QueryRow(
		ctx,
		`SELECT action, data, hash
		   FROM public.provider_audit_events
		  WHERE seq = $1`,
		wormEvent.Seq,
	).Scan(&action, &data, &eventHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return IRWORMCompanionRecord{}, fmt.Errorf(
			"audit: protected provider event %d was pruned before IR coverage",
			wormEvent.Seq,
		)
	}
	if err != nil {
		return IRWORMCompanionRecord{}, fmt.Errorf(
			"audit: read protected provider event %d: %w",
			wormEvent.Seq,
			err,
		)
	}
	if action != wormEvent.Action || eventHash != wormEvent.Hash {
		return IRWORMCompanionRecord{}, errors.New(
			"audit: protected provider row differs from signed WORM event",
		)
	}
	tenantID, ok := data["tenant"].(string)
	if !ok || !canonicalIRTenantID.MatchString(tenantID) {
		return IRWORMCompanionRecord{}, errors.New(
			"audit: protected provider event has no canonical IR tenant",
		)
	}
	stage, err := s.readIRWORMStage(
		ctx,
		q,
		tenantID,
		wormEvent.Seq,
	)
	if err != nil {
		return IRWORMCompanionRecord{}, err
	}
	if stage.EventRef != wormEvent.Hash {
		return IRWORMCompanionRecord{}, errors.New(
			"audit: IR stage event reference differs from signed WORM event",
		)
	}
	if err := s.verifyIRStageRecord(tenantID, stage); err != nil {
		return IRWORMCompanionRecord{}, err
	}
	encodedStage, err := (crypto.Sealed{
		KeyID: stage.KeyID, WrappedDEK: stage.WrappedDEK,
		Ciphertext: stage.Ciphertext,
	}).Encode()
	if err != nil {
		return IRWORMCompanionRecord{}, err
	}
	defer crypto.Zeroize(encodedStage)
	provider, err := s.keys.WrapProviderForTenant(ctx, tenantID)
	if err != nil {
		return IRWORMCompanionRecord{}, fmt.Errorf(
			"audit: resolve tenant IR WORM wrapping key: %w",
			err,
		)
	}
	sealed, err := crypto.NewEnvelope(provider).Seal(
		ctx,
		encodedStage,
		irWORMStageAAD(tenantID, wormEvent.Seq, segmentHash),
	)
	if err != nil {
		return IRWORMCompanionRecord{}, fmt.Errorf(
			"audit: seal IR WORM binding: %w",
			err,
		)
	}
	record := IRWORMCompanionRecord{
		AuditSeq:  wormEvent.Seq,
		StageHash: stage.Hash, KeyID: sealed.KeyID,
		WrappedDEK: sealed.WrappedDEK, Ciphertext: sealed.Ciphertext,
	}
	record.Hash, err = hashCanonical(irWORMRecordHash{
		Domain: irWORMBindingDomain, TenantID: tenantID,
		AuditSeq: wormEvent.Seq, WORMSegmentHash: segmentHash,
		StageHash: stage.Hash, KeyID: sealed.KeyID,
		WrappedDEK: sealed.WrappedDEK, Ciphertext: sealed.Ciphertext,
	})
	if err != nil {
		return IRWORMCompanionRecord{}, err
	}
	record.Signature, err = crypto.SignEd25519(
		s.signingKey,
		[]byte(record.Hash),
	)
	if err != nil {
		return IRWORMCompanionRecord{}, fmt.Errorf(
			"audit: sign IR WORM binding: %w",
			err,
		)
	}
	return record, nil
}

func (s *IRStagePG) readIRWORMStage(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	auditSeq int64,
) (irStoredStage, error) {
	var stage irStoredStage
	if err := withIRTenantRoute(ctx, q, tenantID, func() error {
		err := q.QueryRow(
			ctx,
			`SELECT audit_seq, chain_pos, event_ref, key_id, wrapped_dek,
			        ciphertext, prev_hash, hash, signature
			   FROM ir_attribution_records
			  WHERE tenant_id = $1::uuid AND audit_seq = $2`,
			tenantID,
			auditSeq,
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
			return fmt.Errorf(
				"audit: protected WORM event %d lacks retained encrypted IR attribution",
				auditSeq,
			)
		}
		return err
	}); err != nil {
		return irStoredStage{}, err
	}
	return stage, nil
}

func (s *IRStagePG) verifyIRStageRecord(
	tenantID string,
	record irStoredStage,
) error {
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
		return errors.New("audit: IR stage hash differs before WORM binding")
	}
	ok, err := crypto.VerifyEd25519(
		s.verifyKey,
		[]byte(record.Hash),
		record.Signature,
	)
	if err != nil || !ok {
		return errors.New("audit: IR stage signature differs before WORM binding")
	}
	return nil
}

func (s *IRStagePG) verifyIRWORMCompanionStages(
	ctx context.Context,
	q tenancy.Querier,
	companion IRWORMCompanion,
	segment WormSegment,
) error {
	eventRefs := make(map[int64]string, len(segment.Events))
	for _, event := range segment.Events {
		eventRefs[event.Seq] = event.Hash
	}
	for _, record := range companion.Records {
		tenantID, stage, err := s.resolveIRWORMStage(
			ctx,
			q,
			record,
			companion.WORMSegmentHash,
			eventRefs[record.AuditSeq],
		)
		if err != nil {
			return err
		}
		if stage.Hash != record.StageHash ||
			stage.EventRef != eventRefs[record.AuditSeq] {
			return errors.New(
				"audit: retained IR stage differs from signed WORM companion",
			)
		}
		if err := s.verifyIRStageRecord(tenantID, stage); err != nil {
			return err
		}
	}
	return nil
}

func (s *IRStagePG) resolveIRWORMStage(
	ctx context.Context,
	q tenancy.Querier,
	record IRWORMCompanionRecord,
	segmentHash, eventRef string,
) (string, irStoredStage, error) {
	rows, err := q.Query(
		ctx,
		`SELECT id::text
		   FROM public.tenants
		  ORDER BY id`,
	)
	if err != nil {
		return "", irStoredStage{}, fmt.Errorf(
			"audit: enumerate IR WORM stage routes: %w",
			err,
		)
	}
	var tenants []string
	for rows.Next() {
		var tenantID string
		if err := rows.Scan(&tenantID); err != nil {
			rows.Close()
			return "", irStoredStage{}, err
		}
		tenants = append(tenants, tenantID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", irStoredStage{}, err
	}
	rows.Close()

	var matchedTenant string
	var matchedStage irStoredStage
	for _, tenantID := range tenants {
		stage, exists, err := s.readOptionalIRWORMStage(
			ctx,
			q,
			tenantID,
			record.AuditSeq,
		)
		if err != nil {
			return "", irStoredStage{}, err
		}
		if !exists ||
			stage.Hash != record.StageHash ||
			stage.EventRef != eventRef {
			continue
		}
		if err := s.verifyIRStageRecord(tenantID, stage); err != nil {
			return "", irStoredStage{}, err
		}
		want, err := hashCanonical(irWORMRecordHash{
			Domain: irWORMBindingDomain, TenantID: tenantID,
			AuditSeq: record.AuditSeq, WORMSegmentHash: segmentHash,
			StageHash: record.StageHash, KeyID: record.KeyID,
			WrappedDEK: record.WrappedDEK, Ciphertext: record.Ciphertext,
		})
		if err != nil {
			return "", irStoredStage{}, err
		}
		if want != record.Hash {
			continue
		}
		if matchedTenant != "" {
			return "", irStoredStage{}, errors.New(
				"audit: IR WORM companion resolves to multiple tenant stages",
			)
		}
		matchedTenant, matchedStage = tenantID, stage
	}
	if matchedTenant == "" {
		return "", irStoredStage{}, fmt.Errorf(
			"audit: protected WORM event %d lacks one matching encrypted IR stage",
			record.AuditSeq,
		)
	}
	return matchedTenant, matchedStage, nil
}

func (s *IRStagePG) readOptionalIRWORMStage(
	ctx context.Context,
	q tenancy.Querier,
	tenantID string,
	auditSeq int64,
) (irStoredStage, bool, error) {
	var stage irStoredStage
	var exists bool
	err := withIRTenantRoute(ctx, q, tenantID, func() error {
		err := q.QueryRow(
			ctx,
			`SELECT audit_seq, chain_pos, event_ref, key_id, wrapped_dek,
			        ciphertext, prev_hash, hash, signature
			   FROM ir_attribution_records
			  WHERE tenant_id = $1::uuid AND audit_seq = $2`,
			tenantID,
			auditSeq,
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
			return nil
		}
		if err == nil {
			exists = true
		}
		return err
	})
	if err != nil {
		return irStoredStage{}, false, err
	}
	return stage, exists, nil
}

func (s *IRStagePG) decodeAndVerifyIRWORMCompanion(
	raw []byte,
	segment WormSegment,
	segmentHash string,
) (IRWORMCompanion, error) {
	var companion IRWORMCompanion
	if err := json.Unmarshal(raw, &companion); err != nil {
		return IRWORMCompanion{}, err
	}
	canonical, err := companion.canonicalJSON()
	if err != nil {
		return IRWORMCompanion{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return IRWORMCompanion{}, errors.New(
			"audit: IR WORM companion is not canonical JSON",
		)
	}
	if err := s.verifyIRWORMCompanion(companion, segment, segmentHash); err != nil {
		return IRWORMCompanion{}, err
	}
	return companion, nil
}

func (s *IRStagePG) verifyIRWORMCompanion(
	companion IRWORMCompanion,
	segment WormSegment,
	segmentHash string,
) error {
	if companion.FormatVersion != 1 ||
		companion.Domain != irWORMCompanionDomain ||
		companion.FromSeq != segment.FromSeq ||
		companion.ToSeq != segment.ToSeq ||
		companion.WORMSegmentHash != segmentHash ||
		len(companion.Records) > maxIRWORMCompanionRecords {
		return errors.New("audit: IR WORM companion metadata differs from segment")
	}
	protected := make(map[int64]struct{})
	for _, event := range segment.Events {
		isProtected, err := classifyIRWORMAction(event.Action)
		if err != nil {
			return err
		}
		if isProtected {
			protected[event.Seq] = struct{}{}
		}
	}
	seen := make(map[int64]struct{}, len(companion.Records))
	var previous int64
	for i, record := range companion.Records {
		if record.AuditSeq < segment.FromSeq ||
			record.AuditSeq > segment.ToSeq ||
			!irLowerHex64.MatchString(record.StageHash) ||
			!irLowerHex64.MatchString(record.Hash) ||
			len(record.KeyID) == 0 || len(record.KeyID) > 256 ||
			len(record.WrappedDEK) == 0 ||
			len(record.WrappedDEK) > maxIRWrappedDEKBytes ||
			len(record.Ciphertext) == 0 ||
			len(record.Ciphertext) > maxIRCiphertextBytes ||
			len(record.Signature) != crypto.Ed25519SignatureSize {
			return errors.New("audit: IR WORM companion record has invalid shape")
		}
		if i > 0 && record.AuditSeq <= previous {
			return errors.New("audit: IR WORM companion records are not ordered")
		}
		previous = record.AuditSeq
		if _, ok := protected[record.AuditSeq]; !ok {
			return errors.New("audit: IR WORM companion includes an unprotected event")
		}
		if _, duplicate := seen[record.AuditSeq]; duplicate {
			return errors.New("audit: IR WORM companion duplicates an event")
		}
		seen[record.AuditSeq] = struct{}{}
		ok, err := crypto.VerifyEd25519(
			s.verifyKey,
			[]byte(record.Hash),
			record.Signature,
		)
		if err != nil || !ok {
			return errors.New("audit: IR WORM companion record signature invalid")
		}
	}
	for seq := range protected {
		if _, ok := seen[seq]; !ok {
			return fmt.Errorf(
				"audit: protected WORM event %d lacks encrypted attribution",
				seq,
			)
		}
	}
	payload, err := companion.canonicalPayloadJSON()
	if err != nil {
		return err
	}
	if companion.PayloadHash != hex.EncodeToString(crypto.Hash(payload)) {
		return errors.New("audit: IR WORM companion payload hash mismatch")
	}
	ok, err := crypto.VerifyEd25519(
		s.verifyKey,
		[]byte(companion.PayloadHash),
		companion.Signature,
	)
	if err != nil || !ok {
		return errors.New("audit: IR WORM companion signature invalid")
	}
	return nil
}

func (s *IRStagePG) irCoverageRangeExists(
	ctx context.Context,
	q tenancy.Querier,
	fromSeq, toSeq int64,
) (bool, error) {
	var exists bool
	if err := q.QueryRow(
		ctx,
		`SELECT EXISTS (
		     SELECT 1
		       FROM public.ir_attribution_worm_coverage
		      WHERE from_seq = $1 AND to_seq = $2
		 )`,
		fromSeq,
		toSeq,
	).Scan(&exists); err != nil {
		return false, fmt.Errorf("audit: inspect IR WORM coverage: %w", err)
	}
	return exists, nil
}

// commitIRWORMCoverageLocked finalizes one coverage step in the provider
// transaction that already holds audit:ir:worm-coverage.
func (s *IRStagePG) commitIRWORMCoverageLocked(
	ctx context.Context,
	q tenancy.Querier,
	companion IRWORMCompanion,
	companionKey, companionHash string,
) error {
	if !irLowerHex64.MatchString(companionHash) {
		return errors.New("audit: invalid IR WORM companion object hash")
	}
	head, err := s.readIRCoverageHead(ctx, q, true)
	if err != nil {
		return err
	}
	if err := s.verifyIRCoverageHead(head); err != nil {
		return err
	}
	existing, found, err := s.readIRCoverageRecord(
		ctx,
		q,
		companion.FromSeq,
	)
	if err != nil {
		return err
	}
	if found {
		if existing.ToSeq != companion.ToSeq ||
			existing.WORMSegmentHash != companion.WORMSegmentHash ||
			existing.CompanionKey != companionKey ||
			existing.CompanionHash != companionHash ||
			existing.ProtectedRecords != int64(len(companion.Records)) {
			return errors.New("audit: conflicting committed IR WORM coverage")
		}
		return s.verifyIRCoverageRecord(existing)
	}
	if companion.FromSeq != head.CoveredSeq+1 {
		return fmt.Errorf(
			"audit: IR WORM coverage is not contiguous: want from_seq %d, got %d",
			head.CoveredSeq+1,
			companion.FromSeq,
		)
	}
	record := irCoverageRecord{
		FromSeq: companion.FromSeq, ToSeq: companion.ToSeq,
		WORMSegmentHash: companion.WORMSegmentHash,
		CompanionKey:    companionKey, CompanionHash: companionHash,
		ProtectedRecords: int64(len(companion.Records)),
		PrevHash:         head.LastHash,
	}
	record.Hash, err = hashCanonical(irCoverageHash{
		Domain: irWORMCoverageDomain, FromSeq: record.FromSeq,
		ToSeq: record.ToSeq, WORMSegmentHash: record.WORMSegmentHash,
		CompanionKey:     record.CompanionKey,
		CompanionHash:    record.CompanionHash,
		ProtectedRecords: record.ProtectedRecords,
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
		return fmt.Errorf("audit: sign IR WORM coverage: %w", err)
	}
	if _, err := q.Exec(
		ctx,
		`INSERT INTO public.ir_attribution_worm_coverage
		    (from_seq, to_seq, worm_segment_hash, companion_key,
		     companion_hash, protected_records, prev_hash, hash, signature)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		record.FromSeq,
		record.ToSeq,
		record.WORMSegmentHash,
		record.CompanionKey,
		record.CompanionHash,
		record.ProtectedRecords,
		record.PrevHash,
		record.Hash,
		record.Signature,
	); err != nil {
		return fmt.Errorf("audit: insert IR WORM coverage: %w", err)
	}
	next := irCoverageHead{
		CoveredSeq: companion.ToSeq,
		LastHash:   record.Hash, CompanionHash: companionHash,
	}
	next.Signature, err = s.signIRCoverageHead(next)
	if err != nil {
		return err
	}
	tag, err := q.Exec(
		ctx,
		`UPDATE public.ir_attribution_worm_coverage_head
		    SET covered_seq = $1,
		        last_hash = $2,
		        companion_hash = $3,
		        signature = $4,
		        updated_at = now()
		  WHERE singleton
		    AND covered_seq = $5
		    AND last_hash = $6`,
		next.CoveredSeq,
		next.LastHash,
		next.CompanionHash,
		next.Signature,
		head.CoveredSeq,
		head.LastHash,
	)
	if err != nil {
		return fmt.Errorf("audit: advance IR WORM coverage head: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("audit: IR WORM coverage head changed concurrently")
	}
	return nil
}

// CoverageWatermark verifies the continuous signed coverage chain from
// provider sequence one, the exact WORM-segment bytes, and every persisted
// companion object before returning a retention-authorizing sequence.
func (s *IRStagePG) CoverageWatermark(
	ctx context.Context,
	objects objectstore.Store,
	verifyWORM irWORMSegmentVerifier,
) (int64, error) {
	if s == nil || s.pool == nil || objects == nil || verifyWORM == nil {
		return 0, errors.New("audit: IR WORM coverage verifier is unavailable")
	}
	var covered int64
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(
			ctx,
			`SELECT from_seq, to_seq, worm_segment_hash, companion_key,
			        companion_hash, protected_records, prev_hash, hash, signature
			   FROM public.ir_attribution_worm_coverage
			  ORDER BY from_seq`,
		)
		if err != nil {
			return fmt.Errorf("audit: read IR WORM coverage chain: %w", err)
		}
		defer rows.Close()
		wantSeq := int64(1)
		prevHash := ""
		lastCompanionHash := ""
		var records int64
		expectedCompanions := make(map[string]struct{})
		coverageRecords := make([]irCoverageRecord, 0)
		for rows.Next() {
			var record irCoverageRecord
			if err := rows.Scan(
				&record.FromSeq,
				&record.ToSeq,
				&record.WORMSegmentHash,
				&record.CompanionKey,
				&record.CompanionHash,
				&record.ProtectedRecords,
				&record.PrevHash,
				&record.Hash,
				&record.Signature,
			); err != nil {
				return err
			}
			if record.FromSeq != wantSeq || record.PrevHash != prevHash {
				return errors.New("audit: IR WORM coverage chain is discontinuous")
			}
			if err := s.verifyIRCoverageRecord(record); err != nil {
				return err
			}
			coverageRecords = append(coverageRecords, record)
			records++
			expectedCompanions[record.CompanionKey] = struct{}{}
			covered = record.ToSeq
			wantSeq = covered + 1
			prevHash = record.Hash
			lastCompanionHash = record.CompanionHash
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		for _, record := range coverageRecords {
			if err := s.verifyIRCoverageObjects(
				ctx,
				q,
				objects,
				verifyWORM,
				record,
			); err != nil {
				return err
			}
		}
		keys, err := objects.ListLimited(
			ctx,
			irWORMPrefix,
			maxIRWORMCompanionObjects,
		)
		if err != nil {
			return fmt.Errorf("audit: inventory IR WORM companions: %w", err)
		}
		if len(keys) != len(expectedCompanions) {
			return errors.New(
				"audit: IR WORM companion inventory differs from signed coverage",
			)
		}
		for _, key := range keys {
			if _, ok := expectedCompanions[key]; !ok {
				return fmt.Errorf(
					"audit: unreferenced IR WORM companion %q",
					key,
				)
			}
		}
		head, exists, err := s.readOptionalIRCoverageHead(ctx, q, false)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("audit: IR WORM coverage head is missing")
		}
		if err := s.verifyIRCoverageHead(head); err != nil {
			return err
		}
		if head.CoveredSeq != covered ||
			head.LastHash != prevHash ||
			head.CompanionHash != lastCompanionHash {
			return errors.New("audit: IR WORM coverage head differs from chain")
		}
		return nil
	})
	return covered, err
}

func (s *IRStagePG) verifyIRCoverageObjects(
	ctx context.Context,
	q tenancy.Querier,
	objects objectstore.Store,
	verifyWORM irWORMSegmentVerifier,
	record irCoverageRecord,
) error {
	wormKey := fmt.Sprintf(
		"%ssegment-%012d-%012d.json",
		wormPrefix,
		record.FromSeq,
		record.ToSeq,
	)
	verified, err := verifyWORM(
		ctx,
		wormKey,
		record.WORMSegmentHash,
	)
	if err != nil {
		return fmt.Errorf("audit: verify covered WORM segment: %w", err)
	}
	companion, err := objects.GetLimited(
		ctx,
		record.CompanionKey,
		maxIRWORMCompanionBytes,
	)
	if err != nil {
		return fmt.Errorf("audit: covered IR WORM companion is unavailable: %w", err)
	}
	if companion.ContentType != irWORMCompanionContentType ||
		hex.EncodeToString(crypto.Hash(companion.Data)) != record.CompanionHash {
		return errors.New("audit: covered IR WORM companion object mismatch")
	}
	decoded, err := s.decodeAndVerifyIRWORMCompanion(
		companion.Data,
		verified.segment,
		record.WORMSegmentHash,
	)
	if err != nil {
		return err
	}
	if int64(len(decoded.Records)) != record.ProtectedRecords {
		return errors.New("audit: IR WORM protected-record coverage mismatch")
	}
	if err := s.verifyIRWORMCompanionStages(
		ctx,
		q,
		decoded,
		verified.segment,
	); err != nil {
		return err
	}
	return nil
}

func (s *IRStagePG) readIRCoverageRecord(
	ctx context.Context,
	q tenancy.Querier,
	fromSeq int64,
) (irCoverageRecord, bool, error) {
	var record irCoverageRecord
	err := q.QueryRow(
		ctx,
		`SELECT from_seq, to_seq, worm_segment_hash, companion_key,
		        companion_hash, protected_records, prev_hash, hash, signature
		   FROM public.ir_attribution_worm_coverage
		  WHERE from_seq = $1`,
		fromSeq,
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
		return irCoverageRecord{}, false, nil
	}
	if err != nil {
		return irCoverageRecord{}, false, err
	}
	return record, true, nil
}

func (s *IRStagePG) verifyIRCoverageRecord(record irCoverageRecord) error {
	if record.FromSeq < 1 ||
		record.ToSeq < record.FromSeq ||
		!irLowerHex64.MatchString(record.WORMSegmentHash) ||
		record.CompanionKey != irWORMCompanionKey(record.FromSeq, record.ToSeq) ||
		!irLowerHex64.MatchString(record.CompanionHash) ||
		record.ProtectedRecords < 0 ||
		record.ProtectedRecords > maxIRWORMCompanionRecords ||
		(record.PrevHash != "" && !irLowerHex64.MatchString(record.PrevHash)) ||
		!irLowerHex64.MatchString(record.Hash) ||
		len(record.Signature) != crypto.Ed25519SignatureSize {
		return errors.New("audit: IR WORM coverage record has invalid shape")
	}
	want, err := hashCanonical(irCoverageHash{
		Domain: irWORMCoverageDomain, FromSeq: record.FromSeq, ToSeq: record.ToSeq,
		WORMSegmentHash: record.WORMSegmentHash,
		CompanionKey:    record.CompanionKey, CompanionHash: record.CompanionHash,
		ProtectedRecords: record.ProtectedRecords, PrevHash: record.PrevHash,
	})
	if err != nil {
		return err
	}
	if record.Hash != want {
		return errors.New("audit: IR WORM coverage record hash mismatch")
	}
	ok, err := crypto.VerifyEd25519(
		s.verifyKey,
		[]byte(record.Hash),
		record.Signature,
	)
	if err != nil || !ok {
		return errors.New("audit: IR WORM coverage record signature invalid")
	}
	return nil
}

func (s *IRStagePG) readIRCoverageHead(
	ctx context.Context,
	q tenancy.Querier,
	forUpdate bool,
) (irCoverageHead, error) {
	head, exists, err := s.readOptionalIRCoverageHead(ctx, q, forUpdate)
	if err != nil {
		return irCoverageHead{}, err
	}
	if !exists {
		return irCoverageHead{}, errors.New("audit: IR WORM coverage head is missing")
	}
	return head, nil
}

func (s *IRStagePG) readOptionalIRCoverageHead(
	ctx context.Context,
	q tenancy.Querier,
	forUpdate bool,
) (irCoverageHead, bool, error) {
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	var head irCoverageHead
	err := q.QueryRow(
		ctx,
		`SELECT covered_seq, last_hash, companion_hash, signature
		   FROM public.ir_attribution_worm_coverage_head
		  WHERE singleton`+suffix,
	).Scan(
		&head.CoveredSeq,
		&head.LastHash,
		&head.CompanionHash,
		&head.Signature,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return irCoverageHead{}, false, nil
	}
	if err != nil {
		return irCoverageHead{}, false, err
	}
	return head, true, nil
}

func (s *IRStagePG) signIRCoverageHead(head irCoverageHead) ([]byte, error) {
	raw, err := json.Marshal(irCoverageHeadHash{
		Domain: irWORMCoverageHeadDomain, CoveredSeq: head.CoveredSeq,
		LastHash: head.LastHash, CompanionHash: head.CompanionHash,
	})
	if err != nil {
		return nil, err
	}
	signature, err := crypto.SignEd25519(s.signingKey, raw)
	if err != nil {
		return nil, fmt.Errorf("audit: sign IR WORM coverage head: %w", err)
	}
	return signature, nil
}

func (s *IRStagePG) verifyIRCoverageHead(head irCoverageHead) error {
	if head.CoveredSeq == 0 {
		if head.LastHash != "" ||
			head.CompanionHash != "" ||
			len(head.Signature) != 0 {
			return errors.New("audit: empty IR WORM coverage head is malformed")
		}
		return nil
	}
	if !irLowerHex64.MatchString(head.LastHash) ||
		!irLowerHex64.MatchString(head.CompanionHash) ||
		len(head.Signature) != crypto.Ed25519SignatureSize {
		return errors.New("audit: IR WORM coverage head has invalid shape")
	}
	raw, err := json.Marshal(irCoverageHeadHash{
		Domain: irWORMCoverageHeadDomain, CoveredSeq: head.CoveredSeq,
		LastHash: head.LastHash, CompanionHash: head.CompanionHash,
	})
	if err != nil {
		return err
	}
	ok, err := crypto.VerifyEd25519(s.verifyKey, raw, head.Signature)
	if err != nil || !ok {
		return errors.New("audit: IR WORM coverage head signature invalid")
	}
	return nil
}

// VerifyIRStages verifies every routed per-tenant stage chain. It is called
// during IR/WORM startup reconciliation before finite retention is admitted.
func (s *IRStagePG) VerifyIRStages(ctx context.Context) error {
	if s == nil || s.pool == nil {
		return errors.New("audit: IR stage verifier is unavailable")
	}
	var tenants []string
	if err := tenancy.InProvider(
		ctx,
		s.pool,
		func(ctx context.Context, q tenancy.Querier) error {
			rows, err := q.Query(
				ctx,
				`SELECT id::text
				   FROM public.tenants
				  ORDER BY id`,
			)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var tenantID string
				if err := rows.Scan(&tenantID); err != nil {
					return err
				}
				tenants = append(tenants, tenantID)
			}
			return rows.Err()
		},
	); err != nil {
		return fmt.Errorf("audit: list IR stage heads: %w", err)
	}
	for _, tenantID := range tenants {
		if err := s.VerifyTenant(ctx, s.pool, tenantID); err != nil {
			return fmt.Errorf("audit: verify IR stage tenant %s: %w", tenantID, err)
		}
	}
	return nil
}
