// SPDX-License-Identifier: LicenseRef-probectl-TBD

package audit

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
// preserves the hash chain (no old rows are edited) while making future List
// calls project exact structured matches as erased.
func RecordSubjectErasure(ctx context.Context, s tenancy.Scope, actor, subject, reason string) (Event, error) {
	hash := SubjectErasureHash(s.Tenant.String(), subject)
	if hash == "" {
		return Event{}, fmt.Errorf("audit: subject erasure requires a non-empty subject")
	}
	data := map[string]any{"subject_hash": hash}
	if strings.TrimSpace(reason) != "" {
		data["reason"] = strings.TrimSpace(reason)
	}
	return TenantAppend(ctx, s, actor, SubjectErasureAction, "subject:"+hash[:12], data)
}

func subjectErasureHashes(ctx context.Context, s tenancy.Scope) (map[string]struct{}, error) {
	rows, err := s.Q.Query(ctx, `SELECT data FROM audit_events WHERE action = $1`, SubjectErasureAction)
	if err != nil {
		return nil, fmt.Errorf("list audit subject erasures: %w", err)
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var data map[string]any
		if err := json.Unmarshal(raw, &data); err != nil {
			return nil, fmt.Errorf("decode audit subject erasure: %w", err)
		}
		if hash, ok := data["subject_hash"].(string); ok && hash != "" {
			out[hash] = struct{}{}
		}
	}
	return out, rows.Err()
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
