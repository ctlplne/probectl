// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// AIAnswers persists RCA artifacts (U-093): the full cited answer plus the
// model and a hash of the AI configuration that produced it, so a disputed
// answer is reproducible/inspectable later — the audit log records THAT a
// question was asked; this records WHAT was answered and from what evidence.
// Tenant-scoped by RLS (the tenant_isolation policy on ai_answers), and
// optional: the control plane writes here only when answer persistence is
// enabled.
type AIAnswers struct{}

// AIAnswerInput is one answer artifact to persist.
type AIAnswerInput struct {
	AnswerID   string
	Question   string
	RootCause  string
	Confidence string
	Model      string
	ConfigHash string
	Payload    []byte // the full answer JSON (findings + sanitized evidence)
}

// Save inserts an answer artifact within the caller's tenant scope. Saving the
// same answer twice is a no-op (idempotent on (tenant, answer_id)).
func (AIAnswers) Save(ctx context.Context, s tenancy.Scope, in AIAnswerInput) error {
	if _, err := s.Q.Exec(ctx,
		`INSERT INTO ai_answers (tenant_id, answer_id, question, root_cause, confidence, model, config_hash, payload)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 ON CONFLICT (tenant_id, answer_id) DO NOTHING`,
		s.Tenant.String(), in.AnswerID, in.Question, in.RootCause, in.Confidence, in.Model, in.ConfigHash, in.Payload); err != nil {
		return mapWriteErr("ai_answers", err)
	}
	return nil
}

// PruneOlderThan deletes this tenant's artifacts older than the retention
// window (U-093), returning how many were removed. Called opportunistically on
// save — answer volume is low, so retention needs no scheduler.
func (AIAnswers) PruneOlderThan(ctx context.Context, s tenancy.Scope, retention time.Duration) (int64, error) {
	// clock_timestamp() (the actual statement time), not now() (which is the
	// TRANSACTION start) — so a prune run in the SAME transaction as a freshly
	// inserted row still sees that row as older than the cutoff (retention=0
	// means "everything up to now"). In production prune runs in its own tx, so
	// the two are equivalent there; this only matters in-transaction.
	tag, err := s.Q.Exec(ctx,
		`DELETE FROM ai_answers WHERE tenant_id = $1 AND created_at < clock_timestamp() - make_interval(secs => $2)`,
		s.Tenant.String(), retention.Seconds())
	if err != nil {
		return 0, mapWriteErr("ai_answers", err)
	}
	return tag.RowsAffected(), nil
}
