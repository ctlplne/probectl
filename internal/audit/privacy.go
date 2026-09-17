// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package audit

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	// SubjectErasureAction is the append-only marker that tells audit readers to
	// project matching subject identifiers as erased without rewriting old rows.
	SubjectErasureAction = "privacy.subject_erase"

	erasedSubjectValue = "[erased-subject]"
	erasedSubjectKey   = "_erased_subject_key"
	wormRedactedValue  = "[worm-redacted]"
	privacyMetaKey     = "_probectl_privacy"
)

// SubjectErasureHash returns the tenant-scoped subject marker stored in audit
// erasure events. The raw subject is never persisted in the marker: reads hash
// structured actor/target/data values and redact exact matches.
func SubjectErasureHash(tenantID, subject string) string {
	return subjectHash(tenantID, subject)
}

// RecordSubjectErasure appends an erasure marker to the tenant audit chain. It
// preserves the hash chain (no old rows are edited) while atomically persisting
// the hash-only projection state that survives normal audit-prefix retention.
func RecordSubjectErasure(ctx context.Context, s tenancy.Scope, actor, subject, _ string) (Event, error) {
	hash := SubjectErasureHash(s.Tenant.String(), subject)
	if hash == "" {
		return Event{}, fmt.Errorf("audit: subject erasure requires a non-empty subject")
	}
	// Use the audit-stream lock before touching the projection table. Retention
	// takes this same lock before capturing rolling-old-writer markers, so this
	// common order prevents a state-row/stream-lock deadlock.
	if err := lockTenantStream(ctx, s.Q, s.Tenant.String()); err != nil {
		return Event{}, fmt.Errorf("lock audit chain for subject erasure: %w", err)
	}
	if _, err := s.Q.Exec(
		ctx,
		`INSERT INTO audit_subject_erasures
		    (tenant_id, subject_hash)
		 VALUES ($1::uuid, $2)
		 ON CONFLICT (tenant_id, subject_hash) DO NOTHING`,
		s.Tenant.String(),
		hash,
	); err != nil {
		return Event{}, fmt.Errorf("persist audit subject erasure: %w", err)
	}
	data := map[string]any{"subject_hash": hash}
	return tenantAppendLocked(ctx, s, actor, SubjectErasureAction, "subject:"+hash[:12], data)
}

func subjectErasureHashes(ctx context.Context, s tenancy.Scope) (map[string]struct{}, error) {
	// The durable table is authoritative after retention. The UNION keeps a
	// rolling old binary safe: its just-appended marker projects immediately,
	// and the retention transaction will capture it before deleting that row.
	rows, err := s.Q.Query(
		ctx,
		`SELECT subject_hash
		   FROM audit_subject_erasures
		 UNION
		 SELECT data->>'subject_hash'
		   FROM audit_events
		  WHERE action = $1`,
		SubjectErasureAction,
	)
	if err != nil {
		return nil, fmt.Errorf("list audit subject erasures: %w", err)
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		if !validSubjectErasureHash(hash) {
			return nil, fmt.Errorf("decode audit subject erasure: invalid subject hash")
		}
		out[hash] = struct{}{}
	}
	return out, rows.Err()
}

func validSubjectErasureHash(hash string) bool {
	if len(hash) != 64 || strings.ToLower(hash) != hash {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

func projectErasedSubjects(ev Event, tenantID string, erased map[string]struct{}) Event {
	if len(erased) == 0 {
		return ev
	}
	out := ev
	changed := false
	if actor, ok := redactSubjectString(out.Actor, tenantID, erased); ok {
		out.Actor = actor
		changed = true
	}
	if target, ok := redactSubjectString(out.Target, tenantID, erased); ok {
		out.Target = target
		changed = true
	}
	if data, ok := redactSubjectValue(out.Data, tenantID, erased); ok {
		if projected, isMap := data.(map[string]any); isMap {
			out.Data = projected
		} else {
			out.Data = map[string]any{"value": data}
		}
		changed = true
	}
	if changed {
		out.Data = withPrivacyProjection(out.Data, "subject-erased")
	}
	return out
}

func subjectHash(tenantID, subject string) string {
	normalized := normalizeSubject(subject)
	if normalized == "" {
		return ""
	}
	sum := crypto.Hash([]byte("probectl.audit.subject.v1\x00" + tenantID + "\x00" + normalized))
	return hex.EncodeToString(sum)
}

func normalizeSubject(subject string) string {
	return strings.ToLower(strings.TrimSpace(subject))
}

func redactSubjectString(s, tenantID string, erased map[string]struct{}) (string, bool) {
	if _, ok := erased[subjectHash(tenantID, s)]; ok {
		return erasedSubjectValue, true
	}
	return s, false
}

func redactSubjectValue(v any, tenantID string, erased map[string]struct{}) (any, bool) {
	switch x := v.(type) {
	case nil:
		return nil, false
	case string:
		return redactSubjectString(x, tenantID, erased)
	case map[string]any:
		out := make(map[string]any, len(x))
		changed := false
		for k, v := range x {
			key := k
			if redactedKey, ok := redactSubjectString(k, tenantID, erased); ok {
				key = redactedKey
				changed = true
			}
			val, ok := redactSubjectValue(v, tenantID, erased)
			if ok {
				changed = true
			}
			if _, exists := out[key]; exists && key == erasedSubjectValue {
				key = erasedSubjectKey
			}
			out[key] = val
		}
		return out, changed
	case []any:
		out := make([]any, len(x))
		changed := false
		for i, v := range x {
			val, ok := redactSubjectValue(v, tenantID, erased)
			out[i] = val
			if ok {
				changed = true
			}
		}
		return out, changed
	default:
		return v, false
	}
}

func withPrivacyProjection(data map[string]any, projection string) map[string]any {
	if data == nil {
		data = map[string]any{}
	}
	cp := make(map[string]any, len(data)+1)
	for k, v := range data {
		cp[k] = v
	}
	cp[privacyMetaKey] = map[string]any{"projection": projection}
	return cp
}

func minimizeEventsForWORM(events []Event) []Event {
	out := make([]Event, len(events))
	for i, ev := range events {
		out[i] = minimizeEventForWORM(ev)
	}
	return out
}

func minimizeEventForWORM(ev Event) Event {
	out := ev
	out.Actor = wormRedactedValue
	if out.Target != "" {
		out.Target = wormRedactedValue
	}
	out.Data = map[string]any{
		privacyMetaKey: map[string]any{
			"projection": "worm-minimized",
			"hash":       ev.Hash,
		},
	}
	return out
}

// SubjectErasureReceipt is one recorded verifiable deletion, as an auditor reads
// it: the subject is present only as its salted hash, never as an identifier.
type SubjectErasureReceipt struct {
	SubjectHash string    `json:"subject_hash"`
	RecordedAt  time.Time `json:"recorded_at"`
}

// SubjectErasureReceipts lists the tenant's durable deletion receipts, newest
// first and bounded. It exists so the auditor bundle can carry proof that a
// deletion happened without the caller reaching into this package's tables
// (P7). The subject hash is the proof: it is derived from the tenant and the
// subject, so a receipt binds to one subject in one tenant and to nothing else.
func SubjectErasureReceipts(ctx context.Context, s tenancy.Scope, limit int) ([]SubjectErasureReceipt, error) {
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	rows, err := s.Q.Query(ctx,
		`SELECT subject_hash, created_at
		   FROM audit_subject_erasures
		  ORDER BY created_at DESC
		  LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list subject erasure receipts: %w", err)
	}
	defer rows.Close()
	var out []SubjectErasureReceipt
	for rows.Next() {
		var r SubjectErasureReceipt
		if err := rows.Scan(&r.SubjectHash, &r.RecordedAt); err != nil {
			return nil, err
		}
		if !validSubjectErasureHash(r.SubjectHash) {
			continue
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
