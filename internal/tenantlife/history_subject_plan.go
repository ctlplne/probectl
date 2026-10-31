// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store/flowconversation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var errSubjectDirectoryPlan = errors.New("tenantlife: private subject directory plan refused")

type subjectDirectoryWire struct {
	Version          int      `json:"version"`
	Tenant           string   `json:"tenant"`
	Subject          string   `json:"subject"`
	Kind             string   `json:"kind"`
	ID               string   `json:"id"`
	DirectoryAliases []string `json:"directory_aliases"`
	Aliases          []string `json:"aliases"`
	SessionIDs       []string `json:"session_ids"`
	MCPTokenIDs      []string `json:"mcp_token_ids"`
}

type subjectDirectorySnapshot struct{ value *subjectDirectoryWire }

func (subjectDirectorySnapshot) MarshalJSON() ([]byte, error) { return nil, errSubjectDirectoryPlan }
func (*subjectDirectorySnapshot) UnmarshalJSON([]byte) error  { return errSubjectDirectoryPlan }
func (subjectDirectorySnapshot) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "tenantlife.subjectDirectorySnapshot[private]")
}
func (s subjectDirectorySnapshot) release() {
	if s.value != nil {
		clear(s.value.Aliases)
		clear(s.value.DirectoryAliases)
		clear(s.value.SessionIDs)
		clear(s.value.MCPTokenIDs)
		*s.value = subjectDirectoryWire{}
	}
}

type preparedHistorySubject struct {
	codec    *flowconversation.Codec
	plan     flowconversation.SubjectErasurePlan
	snapshot subjectDirectorySnapshot
	schema   string
	budget   int
}

func (p *preparedHistorySubject) release() {
	if p != nil {
		p.plan.Release()
		p.snapshot.release()
	}
}

func historySubjectAuthority(ctx context.Context, tenant string, current flowconversation.AuthorizeMaintenance) error {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound.String() != tenant || !canonicalSubjectID(tenant) || auth.PrincipalFrom(ctx) != nil || current == nil {
		return flowconversation.ErrMessageDenied
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return current(ctx, tenant)
}

func historySubjectSchema(ctx context.Context, tenant string) (string, error) {
	target, err := tenancy.CurrentRouter().TargetsFor(ctx, tenant)
	if err != nil {
		return "", err
	}
	if target.PGSchema == "" {
		return "public", nil
	}
	return target.PGSchema, nil
}

// Directory locks are short SQL-only approval/reconciliation locks. Source,
// crypto and current authorization callbacks execute outside this transaction.
func lockSubjectDirectory(ctx context.Context, sc tenancy.Scope, schema string) error {
	var current string
	if err := sc.Q.QueryRow(ctx, `SELECT current_schema()`).Scan(&current); err != nil {
		return err
	}
	if current != schema {
		return flowconversation.ErrJournalUnavailable
	}
	var names []string
	for _, table := range []string{"mcp_tokens", "service_accounts", "sessions", "users"} {
		names = append(names, pgx.Identifier{schema, table}.Sanitize())
	}
	if _, err := sc.Q.Exec(ctx, "LOCK TABLE "+strings.Join(names, ",")+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return err
	}
	return tenancy.AssertPostureTx(ctx, sc.Q)
}

func (e *Engine) prepareHistorySubject(ctx context.Context, tenant, operation, subject string, budget flowconversation.CodecBudget, current flowconversation.AuthorizeMaintenance) (preparedHistorySubject, error) {
	if err := historySubjectAuthority(ctx, tenant, current); err != nil {
		return preparedHistorySubject{}, err
	}
	codec, err := flowconversation.NewCodec(budget)
	if err != nil {
		return preparedHistorySubject{}, err
	}
	if e == nil || e.pool == nil {
		return preparedHistorySubject{}, flowconversation.ErrJournalUnavailable
	}
	schema, err := historySubjectSchema(ctx, tenant)
	if err != nil {
		return preparedHistorySubject{}, err
	}
	var snapshot subjectDirectorySnapshot
	err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), e.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if err := lockSubjectDirectory(ctx, sc, schema); err != nil {
			return err
		}
		var err error
		snapshot, err = e.captureHistorySubjectDirectory(ctx, sc, strings.TrimSpace(subject), budget.PlainBytes)
		return err
	})
	if err != nil {
		snapshot.release()
		return preparedHistorySubject{}, err
	}
	if err := historySubjectAuthority(ctx, tenant, current); err != nil {
		snapshot.release()
		return preparedHistorySubject{}, err
	}
	application, err := json.Marshal(snapshot.value)
	if err != nil {
		snapshot.release()
		return preparedHistorySubject{}, errSubjectDirectoryPlan
	}
	defer clear(application)
	plan, err := codec.PrepareSubjectErasurePlan(ctx, operation, snapshot.value.Subject, snapshot.value.Aliases, application)
	if err != nil {
		snapshot.release()
		return preparedHistorySubject{}, err
	}
	return preparedHistorySubject{codec, plan, snapshot, schema, budget.PlainBytes}, nil
}

func (e *Engine) beginPreparedHistorySubject(ctx context.Context, prepared preparedHistorySubject, current flowconversation.AuthorizeMaintenance) (flowconversation.Invalidation, error) {
	if prepared.snapshot.value == nil || e == nil || e.pool == nil {
		return flowconversation.Invalidation{}, errSubjectDirectoryPlan
	}
	if err := historySubjectAuthority(ctx, prepared.snapshot.value.Tenant, current); err != nil {
		return flowconversation.Invalidation{}, err
	}
	// The decoded application in the immutable plan is approval authority;
	// a mutable preparation projection must never substitute for its bytes.
	approved, err := decodeSubjectDirectory(ctx, prepared.snapshot.value.Tenant, prepared.plan, prepared.budget)
	if err != nil {
		return flowconversation.Invalidation{}, err
	}
	defer approved.release()
	return flowconversation.NewJournal(e.pool).BeginSubjectInvalidation(ctx, prepared.codec, prepared.plan, current, func(ctx context.Context, sc tenancy.Scope) error {
		state, err := e.reconcileHistorySubjectDirectory(ctx, sc, approved, prepared.schema, prepared.budget)
		if err != nil {
			return err
		}
		if !slices.Equal(state.directoryAliases, approved.value.DirectoryAliases) || !slices.Equal(state.sessionIDs, approved.value.SessionIDs) || !slices.Equal(state.mcpTokenIDs, approved.value.MCPTokenIDs) {
			return flowconversation.ErrJournalConflict
		}
		return nil
	})
}

func decodeSubjectDirectory(ctx context.Context, tenant string, plan flowconversation.SubjectErasurePlan, budget int) (subjectDirectorySnapshot, error) {
	var result subjectDirectorySnapshot
	err := plan.VisitSelector(ctx, func(subject string, aliases []string, application []byte) error {
		if budget <= 0 || len(application) > budget {
			return flowconversation.ErrMessageBudget
		}
		var value subjectDirectoryWire
		decoder := json.NewDecoder(bytes.NewReader(application))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&value); err != nil {
			return errSubjectDirectoryPlan
		}
		canonical, err := json.Marshal(value)
		defer clear(canonical)
		if err != nil || !bytes.Equal(canonical, application) || value.Version != 1 || value.Tenant != tenant || value.Subject != subject || !slices.Equal(value.Aliases, aliases) || !validDirectorySnapshot(value) {
			return errSubjectDirectoryPlan
		}
		result = subjectDirectorySnapshot{&value}
		return nil
	})
	if err != nil {
		result.release()
		return subjectDirectorySnapshot{}, err
	}
	return result, nil
}

func validDirectorySnapshot(w subjectDirectoryWire) bool {
	if w.Subject == "" || w.Subject != strings.TrimSpace(w.Subject) || !canonicalSubjectID(w.Tenant) || !canonicalDirectoryAliases(w.Aliases) || !canonicalDirectoryAliases(w.DirectoryAliases) || !slices.Contains(w.DirectoryAliases, strings.ToLower(w.Subject)) {
		return false
	}
	if w.Kind == "literal" {
		if w.ID != "" || !isSafeContainsIdentifier(w.Subject) || !slices.Equal(w.DirectoryAliases, []string{strings.ToLower(w.Subject)}) {
			return false
		}
	} else if (w.Kind != "user" && w.Kind != "service_account") || !canonicalSubjectID(w.ID) || !slices.Contains(w.DirectoryAliases, w.ID) {
		return false
	}
	for _, alias := range w.DirectoryAliases {
		if !slices.Contains(w.Aliases, alias) {
			return false
		}
	}
	for _, ids := range [][]string{w.SessionIDs, w.MCPTokenIDs} {
		for i, id := range ids {
			if !canonicalSubjectID(id) || i > 0 && ids[i-1] >= id || !slices.Contains(w.Aliases, id) {
				return false
			}
		}
	}
	union := newSubjectAliasSet(w.Subject)
	for _, values := range [][]string{w.DirectoryAliases, w.SessionIDs, w.MCPTokenIDs} {
		for _, value := range values {
			union.add(value)
		}
	}
	return slices.Equal(union.normalizedValues(), w.Aliases)
}

func canonicalSubjectID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id.String() == value
}
func canonicalDirectoryAliases(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for i, value := range values {
		if value == "" || value != strings.ToLower(strings.TrimSpace(value)) || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}
