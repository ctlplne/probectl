package store

import (
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
)

// Domain models. UUIDs are carried as canonical strings so they map cleanly onto
// OTel resource attributes (S6/S22) and across the API (S9).

// Tenant is the outermost entity and security boundary (F50).
type Tenant struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Organization is the top of the in-tenant hierarchy (Tenant → Org → Team → Project).
type Organization struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Team belongs to an organization.
type Team struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	OrgID     string    `json:"org_id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Project belongs to a team.
type Project struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	TeamID    string    `json:"team_id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// User is a tenant member (per-tenant identity; SSO in S18, SCIM lifecycle in
// S31). ExternalID/UserName are the SCIM identifiers (the IdP's id + userName);
// Attributes are the ABAC subject attributes (e.g. department).
type User struct {
	ID          string            `json:"id"`
	TenantID    string            `json:"tenant_id"`
	Email       string            `json:"email"`
	DisplayName string            `json:"display_name"`
	Status      string            `json:"status"`
	ExternalID  string            `json:"external_id,omitempty"`
	UserName    string            `json:"user_name,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// ScimToken is a per-tenant SCIM bearer-token record (metadata only; the token
// hash is never returned).
type ScimToken struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// RoleBinding assigns a role to a subject within a scope (tenant/org/team/project)
// — the delegated-admin grant.
type RoleBinding struct {
	ID          string `json:"id"`
	SubjectType string `json:"subject_type"`
	SubjectID   string `json:"subject_id"`
	RoleID      string `json:"role_id"`
	ScopeType   string `json:"scope_type"`
	ScopeID     string `json:"scope_id,omitempty"`
}

// Role is a tenant-scoped RBAC role (enforcement lands in S18).
type Role struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ProviderOperator is a provider/MSP operator — NOT a tenant user (F51).
type ProviderOperator struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BreakGlassGrant is a time-bounded, consented, audited grant for an operator to
// access one tenant's data (F51).
type BreakGlassGrant struct {
	ID         string     `json:"id"`
	OperatorID string     `json:"operator_id"`
	TenantID   string     `json:"tenant_id"`
	Reason     string     `json:"reason"`
	Scope      string     `json:"scope"`
	GrantedBy  string     `json:"granted_by"`
	GrantedAt  time.Time  `json:"granted_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	RevokedBy  *string    `json:"revoked_by,omitempty"`
}

// notFound maps a pgx no-rows error to a domain NotFound; other errors pass
// through unchanged.
func notFound(entity string, err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return apierror.NotFound(entity + " not found")
	}
	return err
}
