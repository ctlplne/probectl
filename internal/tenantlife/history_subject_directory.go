// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/store/flowconversation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type subjectDirectoryCurrent struct {
	present                 bool
	directoryAliases        []string
	sessionIDs, mcpTokenIDs []string
	aliases                 subjectAliasSet
}

func (subjectDirectoryCurrent) MarshalJSON() ([]byte, error) { return nil, errSubjectDirectoryPlan }
func (subjectDirectoryCurrent) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "tenantlife.subjectDirectoryCurrent[private]")
}

func (e *Engine) captureHistorySubjectDirectory(ctx context.Context, sc tenancy.Scope, subject string, budget int) (subjectDirectorySnapshot, error) {
	if budget <= 0 || len(subject) > budget {
		return subjectDirectorySnapshot{}, flowconversation.ErrMessageBudget
	}
	aliases, identities, err := e.resolveSubjectDirectory(ctx, sc, subject)
	if err != nil {
		return subjectDirectorySnapshot{}, err
	}
	wire := subjectDirectoryWire{Version: 1, Tenant: sc.Tenant.String(), Subject: subject, Kind: "literal", DirectoryAliases: aliases.normalizedValues()}
	if len(identities) == 1 {
		wire.Kind, wire.ID = identities[0].kind, identities[0].id
	}
	used := len(subject)
	for _, value := range wire.DirectoryAliases {
		if len(value) >= budget-used {
			return subjectDirectorySnapshot{}, flowconversation.ErrMessageBudget
		}
		used += len(value) + 1
	}
	wire.SessionIDs, wire.MCPTokenIDs, err = e.captureHistorySubjectCredentials(ctx, sc, wire, budget-used)
	if err != nil {
		return subjectDirectorySnapshot{}, err
	}
	for _, id := range append(slices.Clone(wire.SessionIDs), wire.MCPTokenIDs...) {
		aliases.add(id)
	}
	wire.Aliases = aliases.normalizedValues()
	if !validDirectorySnapshot(wire) {
		return subjectDirectorySnapshot{}, errSubjectDirectoryPlan
	}
	return subjectDirectorySnapshot{&wire}, nil
}

// Directory-mode credentials belong to the approved stable UUID. Session email
// is deliberately not an identity link: it may survive an earlier rename.
func (e *Engine) captureHistorySubjectCredentials(ctx context.Context, sc tenancy.Scope, approved subjectDirectoryWire, budget int) ([]string, []string, error) {
	if budget <= 0 {
		return nil, nil, flowconversation.ErrMessageBudget
	}
	var sessions, tokens []string
	for _, table := range []struct {
		name string
		dst  *[]string
	}{{"sessions", &sessions}, {"mcp_tokens", &tokens}} {
		exists, err := e.subjectTableExists(ctx, sc, table.name)
		if err != nil {
			return nil, nil, err
		}
		if !exists {
			return nil, nil, errSubjectDirectoryPlan
		}
		predicate, selector := "user_id=$2::uuid", approved.ID
		if approved.Kind == "literal" {
			predicate, selector = "lower(id::text)=$2", strings.ToLower(approved.Subject)
			if table.name == "sessions" {
				predicate = "(lower(id::text)=$2 OR lower(email)=$2)"
			}
		}
		// Identifiers come only from the two fixed entries above.
		rows, err := sc.Q.Query(ctx, `SELECT id::text FROM `+pgIdent(table.name)+` WHERE tenant_id=$1::uuid AND `+predicate+` ORDER BY id`, sc.Tenant.String(), selector)
		if err != nil {
			return nil, nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, nil, err
			}
			if !canonicalSubjectID(id) {
				rows.Close()
				return nil, nil, errSubjectDirectoryPlan
			}
			if len(id) >= budget {
				rows.Close()
				return nil, nil, flowconversation.ErrMessageBudget
			}
			budget -= len(id) + 1
			*table.dst = append(*table.dst, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, nil, err
		}
	}
	return sessions, tokens, nil
}

func (e *Engine) reconcileHistorySubjectDirectory(ctx context.Context, sc tenancy.Scope, snapshot subjectDirectorySnapshot, schema string, budget int) (subjectDirectoryCurrent, error) {
	w := snapshot.value
	if w == nil || w.Tenant != sc.Tenant.String() || !validDirectorySnapshot(*w) {
		return subjectDirectoryCurrent{}, errSubjectDirectoryPlan
	}
	if err := lockSubjectDirectory(ctx, sc, schema); err != nil {
		return subjectDirectoryCurrent{}, err
	}
	// Every original directory alias must still be unowned or belong to the
	// exact approved typed identity. Never re-resolve it into a successor.
	rows, err := sc.Q.Query(ctx, `SELECT 'user',id::text FROM users WHERE tenant_id=$1::uuid AND
 (lower(id::text)=ANY($2::text[]) OR lower(btrim(email))=ANY($2::text[]) OR lower(btrim(COALESCE(user_name,'')))=ANY($2::text[]) OR lower(btrim(COALESCE(external_id,'')))=ANY($2::text[]))
 UNION ALL SELECT 'service_account',id::text FROM service_accounts WHERE tenant_id=$1::uuid AND (lower(id::text)=ANY($2::text[]) OR lower(btrim(name))=ANY($2::text[]))`, w.Tenant, w.DirectoryAliases)
	if err != nil {
		return subjectDirectoryCurrent{}, err
	}
	for rows.Next() {
		var kind, id string
		if err := rows.Scan(&kind, &id); err != nil {
			rows.Close()
			return subjectDirectoryCurrent{}, err
		}
		if kind != w.Kind || id != w.ID {
			rows.Close()
			return subjectDirectoryCurrent{}, flowconversation.ErrJournalConflict
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return subjectDirectoryCurrent{}, err
	}
	current := subjectDirectoryCurrent{aliases: newSubjectAliasSet(w.Subject)}
	for _, alias := range w.Aliases {
		current.aliases.add(alias)
	}
	directory := newSubjectAliasSet("")
	if w.Kind == "literal" {
		directory.add(w.Subject)
	} else {
		identity := subjectIdentity{kind: w.Kind, id: w.ID}
		if w.Kind == "user" {
			err = sc.Q.QueryRow(ctx, `SELECT email,COALESCE(user_name,''),COALESCE(external_id,'') FROM users WHERE tenant_id=$1::uuid AND id=$2::uuid`, w.Tenant, w.ID).Scan(&identity.email, &identity.userName, &identity.externalID)
		} else {
			err = sc.Q.QueryRow(ctx, `SELECT name FROM service_accounts WHERE tenant_id=$1::uuid AND id=$2::uuid`, w.Tenant, w.ID).Scan(&identity.name)
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return subjectDirectoryCurrent{}, err
		}
		current.present = err == nil
		if current.present {
			for _, value := range []string{identity.id, identity.email, identity.userName, identity.externalID, identity.name} {
				directory.add(value)
			}
		}
	}
	current.directoryAliases = directory.normalizedValues()
	current.sessionIDs, current.mcpTokenIDs, err = e.captureHistorySubjectCredentials(ctx, sc, *w, budget)
	if err != nil {
		return subjectDirectoryCurrent{}, err
	}
	for _, values := range [][]string{current.directoryAliases, current.sessionIDs, current.mcpTokenIDs} {
		for _, value := range values {
			current.aliases.add(value)
		}
	}
	used := 0
	for _, value := range current.aliases.values() {
		if len(value) >= budget-used {
			return subjectDirectoryCurrent{}, flowconversation.ErrMessageBudget
		}
		used += len(value) + 1
	}
	return current, nil
}

func (e *Engine) resumeHistorySubject(ctx context.Context, tenant, operation string, budget flowconversation.CodecBudget, current flowconversation.AuthorizeMaintenance) (flowconversation.Invalidation, subjectDirectorySnapshot, subjectDirectoryCurrent, error) {
	if err := historySubjectAuthority(ctx, tenant, current); err != nil {
		return flowconversation.Invalidation{}, subjectDirectorySnapshot{}, subjectDirectoryCurrent{}, err
	}
	codec, err := flowconversation.NewCodec(budget)
	if err != nil || e == nil || e.pool == nil {
		return flowconversation.Invalidation{}, subjectDirectorySnapshot{}, subjectDirectoryCurrent{}, errSubjectDirectoryPlan
	}
	pending, plan, err := flowconversation.NewJournal(e.pool).ResumeSubjectInvalidation(ctx, codec, operation, current)
	defer plan.Release()
	if err != nil {
		return flowconversation.Invalidation{}, subjectDirectorySnapshot{}, subjectDirectoryCurrent{}, err
	}
	snapshot, err := decodeSubjectDirectory(ctx, tenant, plan, budget.PlainBytes)
	if err != nil {
		return flowconversation.Invalidation{}, subjectDirectorySnapshot{}, subjectDirectoryCurrent{}, err
	}
	schema, err := historySubjectSchema(ctx, tenant)
	var state subjectDirectoryCurrent
	if err == nil {
		err = tenancy.InTenant(tenancy.WithSiloTableLock(ctx), e.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			state, err = e.reconcileHistorySubjectDirectory(ctx, sc, snapshot, schema, budget.PlainBytes)
			return err
		})
	}
	if err == nil {
		err = historySubjectAuthority(ctx, tenant, current)
	}
	if err != nil {
		snapshot.release()
		return flowconversation.Invalidation{}, subjectDirectorySnapshot{}, subjectDirectoryCurrent{}, err
	}
	return pending, snapshot, state, nil
}
