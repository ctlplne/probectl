// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// InterfaceRoleConfiguration uses the caller's tenant transaction and writer
// fence. Mutations and their existing tenant audit append must commit together.
// No actor copy, materialized classification or background worker is retained.
type InterfaceRoleConfiguration struct{}

func interfaceRoleScope(ctx context.Context, sc tenancy.Scope, contextID string) (entity.Scope, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant {
		return entity.Scope{}, tenancy.ErrNoTenant
	}
	return (entity.Scope{TenantID: sc.Tenant.String(), ContextID: contextID}).Normalize()
}

func interfaceRoleRevision(text string) (int64, error) {
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value < 0 || strconv.FormatInt(value, 10) != text {
		return 0, entity.ErrInterfaceRoleConflict
	}
	return value, nil
}

func interfaceRoleExpectedVersion(id, revision string) (int64, error) {
	version, err := interfaceRoleRevision(revision)
	if err != nil || (version == 0 && id != "") {
		return 0, entity.ErrInterfaceRoleConflict
	}
	if version > 0 {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return 0, entity.ErrInterfaceRoleConflict
		}
	}
	return version, nil
}

func lockInterfaceRoleContext(ctx context.Context, sc tenancy.Scope, scope entity.Scope) error {
	var exists int
	return sc.Q.QueryRow(ctx, `SELECT 1 FROM entity_contexts WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, scope.TenantID, scope.ContextID).Scan(&exists)
}

// Policy returns the owned context's complete current definition. An absent
// policy is revision0 with an empty definition; an absent context is not found.
// The SQL projection bounds the JSON field before it enters this process.
func (InterfaceRoleConfiguration) Policy(ctx context.Context, sc tenancy.Scope, contextID string, budget entity.InterfaceRolePolicyBudget) (entity.InterfaceRolePolicyRecord, error) {
	scope, err := interfaceRoleScope(ctx, sc, contextID)
	if err != nil {
		return entity.InterfaceRolePolicyRecord{}, err
	}
	if budget.MemoryBytes <= 1024 || budget.WorkUnits <= 0 {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRoleBudget
	}
	var revision int64
	var body []byte
	var at *time.Time
	var oversized bool
	var id string
	var formatVersion int
	err = sc.Q.QueryRow(ctx, `SELECT COALESCE(p.id::text,''),COALESCE(p.revision,0),COALESCE(p.format_version,1),
 CASE WHEN p.definition IS NULL THEN '{"provider_asns":[],"customer_asns":[],"description_rules":[]}'::jsonb
      WHEN octet_length(p.definition::text)<=$3::bigint THEN p.definition ELSE NULL END,
 p.updated_at,COALESCE(octet_length(p.definition::text)>$3::bigint,false)
 FROM entity_contexts c LEFT JOIN interface_role_policies p ON (p.tenant_id,p.context_id)=(c.tenant_id,c.id)
 WHERE c.tenant_id=$1 AND c.id=$2`, scope.TenantID, scope.ContextID, (budget.MemoryBytes-1024)/4).Scan(&id, &revision, &formatVersion, &body, &at, &oversized)
	if err != nil {
		return entity.InterfaceRolePolicyRecord{}, err
	}
	if oversized {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRoleBudget
	}
	if formatVersion != 1 {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRolePolicy
	}
	remaining := budget.MemoryBytes - 1024
	if int64(len(body)) > remaining/4 {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRoleBudget
	}
	budget.MemoryBytes = remaining - 4*int64(len(body))
	var definition entity.InterfaceRolePolicyDefinition
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&definition); err != nil {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRolePolicy
	}
	definition, err = entity.NormalizeInterfaceRolePolicy(ctx, definition, budget)
	if err != nil {
		return entity.InterfaceRolePolicyRecord{}, err
	}
	out := entity.InterfaceRolePolicyRecord{Scope: scope, ID: id, Revision: strconv.FormatInt(revision, 10), Definition: definition}
	if at != nil {
		out.UpdatedAt = *at
	}
	return out, nil
}

// PutPolicy preserves known rule IDs and generates new ones at the crypto
// seam. Input, retained previous definition and encoded publication share the
// positive caller allowance. No row is changed on validation/CAS/admission error.
func (s InterfaceRoleConfiguration) PutPolicy(ctx context.Context, sc tenancy.Scope, contextID, expectedID, expected string, input entity.InterfaceRolePolicyDefinition, budget entity.InterfaceRolePolicyBudget) (entity.InterfaceRolePolicyRecord, error) {
	scope, err := interfaceRoleScope(ctx, sc, contextID)
	if err != nil {
		return entity.InterfaceRolePolicyRecord{}, err
	}
	version, err := interfaceRoleExpectedVersion(expectedID, expected)
	if err != nil {
		return entity.InterfaceRolePolicyRecord{}, err
	}
	if budget.MemoryBytes < 8192 || budget.WorkUnits < 4 {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRoleBudget
	}
	if err := lockInterfaceRoleContext(ctx, sc, scope); err != nil {
		return entity.InterfaceRolePolicyRecord{}, err
	}
	previous, err := s.Policy(ctx, sc, contextID, entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 8 * 3, WorkUnits: budget.WorkUnits / 4})
	if err != nil {
		return entity.InterfaceRolePolicyRecord{}, err
	}
	if previous.ID != expectedID || previous.Revision != expected {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRoleConflict
	}
	inputBudget := entity.InterfaceRolePolicyBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.WorkUnits / 2}
	if int64(len(input.DescriptionRules)) > inputBudget.MemoryBytes/2048 || int64(len(input.DescriptionRules)) > inputBudget.WorkUnits {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRoleBudget
	}
	known := map[string]bool{}
	for _, rule := range previous.Definition.DescriptionRules {
		known[rule.ID] = true
	}
	rules := []entity.InterfaceRoleDescriptionRule{}
	for _, rule := range input.DescriptionRules {
		if err := ctx.Err(); err != nil {
			return entity.InterfaceRolePolicyRecord{}, err
		}
		if rule.ID == "" {
			rule.ID, err = crypto.UUIDv4()
			if err != nil {
				return entity.InterfaceRolePolicyRecord{}, err
			}
		} else if !known[rule.ID] {
			return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRolePolicy
		}
		rules = append(rules, rule)
	}
	input.DescriptionRules = rules
	definition, err := entity.NormalizeInterfaceRolePolicy(ctx, input, inputBudget)
	if err != nil {
		return entity.InterfaceRolePolicyRecord{}, err
	}
	body, err := json.Marshal(definition)
	if err != nil {
		return entity.InterfaceRolePolicyRecord{}, err
	}
	if int64(len(body)) > budget.MemoryBytes/8 {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRoleBudget
	}
	// The already-normalized old value is still bounded by its own retained-state
	// allowance. Compare without retaining a second encoded publication body.
	if previous.Revision != "0" && sameInterfaceRolePolicy(definition, previous.Definition) {
		return previous, nil
	}
	if version == math.MaxInt64 {
		return entity.InterfaceRolePolicyRecord{}, entity.ErrInterfaceRoleConflict
	}
	out := entity.InterfaceRolePolicyRecord{Scope: scope, ID: previous.ID, Definition: definition}
	var next int64
	if version == 0 {
		out.ID, err = crypto.UUIDv4()
		if err != nil {
			return entity.InterfaceRolePolicyRecord{}, err
		}
		err = sc.Q.QueryRow(ctx, `INSERT INTO interface_role_policies(tenant_id,context_id,id,definition)
 VALUES($1,$2,$3,$4::jsonb) ON CONFLICT(tenant_id,context_id) DO NOTHING RETURNING revision,updated_at`, scope.TenantID, scope.ContextID, out.ID, body).Scan(&next, &out.UpdatedAt)
	} else {
		err = sc.Q.QueryRow(ctx, `UPDATE interface_role_policies SET revision=revision+1,definition=$5::jsonb,updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND revision=$4 RETURNING revision,updated_at`, scope.TenantID, scope.ContextID, expectedID, version, body).Scan(&next, &out.UpdatedAt)
	}
	if err != nil {
		return entity.InterfaceRolePolicyRecord{}, interfaceRoleConfigurationError(err)
	}
	out.Revision = strconv.FormatInt(next, 10)
	return out, nil
}

func sameInterfaceRolePolicy(a, b entity.InterfaceRolePolicyDefinition) bool {
	return slices.Equal(a.ProviderASNs, b.ProviderASNs) && slices.Equal(a.CustomerASNs, b.CustomerASNs) && slices.Equal(a.DescriptionRules, b.DescriptionRules)
}

// Override requires an owned canonical interface, including its kind. It does
// not require a currently reporting source: an operator's override survives
// automatic reclassification/source loss until explicit reset or entity erasure.
func (InterfaceRoleConfiguration) Override(ctx context.Context, sc tenancy.Scope, contextID, interfaceID string) (entity.InterfaceRoleOverrideRecord, error) {
	scope, err := interfaceRoleScope(ctx, sc, contextID)
	if err != nil {
		return entity.InterfaceRoleOverrideRecord{}, err
	}
	id, err := uuid.Parse(interfaceID)
	if err != nil || id == uuid.Nil {
		return entity.InterfaceRoleOverrideRecord{}, entity.ErrInterfaceRolePolicy
	}
	out := entity.InterfaceRoleOverrideRecord{Scope: scope, InterfaceID: id.String()}
	var revision int64
	var at *time.Time
	err = sc.Q.QueryRow(ctx, `SELECT COALESCE(o.id::text,''),COALESCE(o.revision,0),COALESCE(o.role,''),o.updated_at
 FROM entities e LEFT JOIN interface_role_overrides o
 ON (o.tenant_id,o.context_id,o.interface_id)=(e.tenant_id,e.context_id,e.id)
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.id=$3 AND e.kind='interface'`, scope.TenantID, scope.ContextID, id.String()).Scan(&out.ID, &revision, &out.Role, &at)
	if err != nil {
		return entity.InterfaceRoleOverrideRecord{}, err
	}
	if revision > 0 && !entity.ValidInterfaceRole(out.Role) {
		return entity.InterfaceRoleOverrideRecord{}, entity.ErrInterfaceRolePolicy
	}
	out.Revision = strconv.FormatInt(revision, 10)
	if at != nil {
		out.UpdatedAt = *at
	}
	return out, nil
}

func (s InterfaceRoleConfiguration) PutOverride(ctx context.Context, sc tenancy.Scope, contextID, interfaceID, expectedID, expected string, role entity.InterfaceRole) (entity.InterfaceRoleOverrideRecord, error) {
	scope, err := interfaceRoleScope(ctx, sc, contextID)
	if err != nil {
		return entity.InterfaceRoleOverrideRecord{}, err
	}
	if !entity.ValidInterfaceRole(role) {
		return entity.InterfaceRoleOverrideRecord{}, entity.ErrInterfaceRolePolicy
	}
	version, err := interfaceRoleExpectedVersion(expectedID, expected)
	if err != nil {
		return entity.InterfaceRoleOverrideRecord{}, entity.ErrInterfaceRoleConflict
	}
	if err := lockInterfaceRoleContext(ctx, sc, scope); err != nil {
		return entity.InterfaceRoleOverrideRecord{}, err
	}
	previous, err := s.Override(ctx, sc, contextID, interfaceID)
	if err != nil {
		return entity.InterfaceRoleOverrideRecord{}, err
	}
	if previous.ID != expectedID || previous.Revision != expected {
		return entity.InterfaceRoleOverrideRecord{}, entity.ErrInterfaceRoleConflict
	}
	if previous.ID != "" && previous.Role == role {
		return previous, nil
	}
	if version == math.MaxInt64 {
		return entity.InterfaceRoleOverrideRecord{}, entity.ErrInterfaceRoleConflict
	}
	id := previous.ID
	if id == "" {
		id, err = crypto.UUIDv4()
		if err != nil {
			return entity.InterfaceRoleOverrideRecord{}, err
		}
	}
	out := previous
	out.ID, out.Role = id, role
	var next int64
	if version == 0 {
		err = sc.Q.QueryRow(ctx, `INSERT INTO interface_role_overrides(tenant_id,context_id,interface_id,id,role)
 VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,context_id,interface_id) DO NOTHING RETURNING revision,updated_at`, scope.TenantID, scope.ContextID, previous.InterfaceID, id, role).Scan(&next, &out.UpdatedAt)
	} else {
		err = sc.Q.QueryRow(ctx, `UPDATE interface_role_overrides SET revision=revision+1,role=$6,updated_at=clock_timestamp()
 WHERE tenant_id=$1 AND context_id=$2 AND interface_id=$3 AND id=$4 AND revision=$5 RETURNING revision,updated_at`, scope.TenantID, scope.ContextID, previous.InterfaceID, expectedID, version, role).Scan(&next, &out.UpdatedAt)
	}
	if err != nil {
		return entity.InterfaceRoleOverrideRecord{}, interfaceRoleConfigurationError(err)
	}
	out.Revision = strconv.FormatInt(next, 10)
	return out, nil
}

func (InterfaceRoleConfiguration) ResetOverride(ctx context.Context, sc tenancy.Scope, contextID, interfaceID, expectedID, expected string) error {
	scope, err := interfaceRoleScope(ctx, sc, contextID)
	if err != nil {
		return err
	}
	version, err := interfaceRoleExpectedVersion(expectedID, expected)
	if err != nil || version == 0 {
		return entity.ErrInterfaceRoleConflict
	}
	if err := lockInterfaceRoleContext(ctx, sc, scope); err != nil {
		return err
	}
	result, err := sc.Q.Exec(ctx, `DELETE FROM interface_role_overrides WHERE tenant_id=$1 AND context_id=$2 AND interface_id=$3 AND id=$4 AND revision=$5`, scope.TenantID, scope.ContextID, interfaceID, expectedID, version)
	if err != nil {
		return interfaceRoleConfigurationError(err)
	}
	if result.RowsAffected() != 1 {
		return entity.ErrInterfaceRoleConflict
	}
	return nil
}

func interfaceRoleConfigurationError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return entity.ErrInterfaceRoleConflict
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503":
			return pgx.ErrNoRows
		case "23505":
			return entity.ErrInterfaceRoleConflict
		case "23514", "22P02":
			return entity.ErrInterfaceRolePolicy
		}
	}
	return err
}
