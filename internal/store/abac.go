package store

import (
	"context"
	"encoding/json"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// ABACPolicies is the tenant-scoped ABAC policy repository (S31, F25). RLS confines
// every policy to its tenant, so one tenant's attribute policies never affect
// another. Policies are evaluated AFTER RBAC (deny-override).
type ABACPolicies struct{}

const abacCols = `id::text, name, effect, permission, subject, resource, priority, enabled`

func scanPolicy(row interface{ Scan(...any) error }, p *auth.Policy) error {
	var effect string
	var subj, res []byte
	if err := row.Scan(&p.ID, &p.Name, &effect, &p.Permission, &subj, &res, &p.Priority, &p.Enabled); err != nil {
		return err
	}
	p.Effect = auth.PolicyEffect(effect)
	p.Subject, p.Resource = nil, nil
	if len(subj) > 0 {
		_ = json.Unmarshal(subj, &p.Subject)
	}
	if len(res) > 0 {
		_ = json.Unmarshal(res, &p.Resource)
	}
	return nil
}

// Create inserts an ABAC policy in the caller's tenant.
func (ABACPolicies) Create(ctx context.Context, s tenancy.Scope, in auth.Policy) (*auth.Policy, error) {
	subj, _ := json.Marshal(orEmptyAttrs(in.Subject))
	res, _ := json.Marshal(orEmptyAttrs(in.Resource))
	perm := in.Permission
	if perm == "" {
		perm = "*"
	}
	var p auth.Policy
	if err := scanPolicy(s.Q.QueryRow(ctx,
		`INSERT INTO abac_policies (tenant_id, name, effect, permission, subject, resource, priority, enabled)
		 VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8) RETURNING `+abacCols,
		s.Tenant.String(), in.Name, string(in.Effect), perm, subj, res, in.Priority, in.Enabled), &p); err != nil {
		return nil, mapWriteErr("abac_policy", err)
	}
	return &p, nil
}

// List returns the tenant's ABAC policies (the evaluation set + the admin view).
func (ABACPolicies) List(ctx context.Context, s tenancy.Scope) ([]auth.Policy, error) {
	rows, err := s.Q.Query(ctx, `SELECT `+abacCols+` FROM abac_policies ORDER BY priority DESC, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []auth.Policy{}
	for rows.Next() {
		var p auth.Policy
		if err := scanPolicy(rows, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Delete removes a tenant's ABAC policy.
func (ABACPolicies) Delete(ctx context.Context, s tenancy.Scope, id string) error {
	_, err := s.Q.Exec(ctx, `DELETE FROM abac_policies WHERE id = $1`, id)
	return err
}
