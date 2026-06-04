// Package scim implements the SCIM 2.0 (RFC 7643 schema / RFC 7644 protocol) wire
// types and patch semantics for probectl's enterprise identity lifecycle (S31, F25).
// It is PURE — no datastore or HTTP-server dependency — so the schema mapping and
// the (strict, IdP-sensitive) PATCH handling are independently testable. The
// control plane maps these types to/from the tenant-scoped user/role store.
package scim

import "time"

// ContentType is the SCIM media type. IdPs are strict: responses use it.
const ContentType = "application/scim+json"

// SCIM schema URNs.
const (
	SchemaUser       = "urn:ietf:params:scim:schemas:core:2.0:User"
	SchemaGroup      = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SchemaEnterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	SchemaList       = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SchemaPatchOp    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	SchemaError      = "urn:ietf:params:scim:api:messages:2.0:Error"
	SchemaSPConfig   = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

// Meta is the SCIM common metadata block.
type Meta struct {
	ResourceType string     `json:"resourceType"`
	Created      *time.Time `json:"created,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Location     string     `json:"location,omitempty"`
}

// Name is the SCIM complex name attribute.
type Name struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// Email is one SCIM email value.
type Email struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

// Enterprise is the enterprise-user extension (we surface department for ABAC).
type Enterprise struct {
	Department string `json:"department,omitempty"`
}

// User is a SCIM core User resource.
type User struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id,omitempty"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *Name       `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []Email     `json:"emails,omitempty"`
	Active      bool        `json:"active"`
	Enterprise  *Enterprise `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	Meta        *Meta       `json:"meta,omitempty"`
}

// PrimaryEmail returns the primary email (or the first), else "".
func (u User) PrimaryEmail() string {
	for _, e := range u.Emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(u.Emails) > 0 {
		return u.Emails[0].Value
	}
	return ""
}

// Member is a SCIM Group member reference.
type Member struct {
	Value   string `json:"value"` // the member user's id
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

// Group is a SCIM core Group resource (mapped to a probectl role).
type Group struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id,omitempty"`
	ExternalID  string   `json:"externalId,omitempty"`
	DisplayName string   `json:"displayName"`
	Members     []Member `json:"members,omitempty"`
	Meta        *Meta    `json:"meta,omitempty"`
}

// ListResponse is a SCIM list/query response envelope.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// NewList builds a ListResponse with the SCIM list schema set.
func NewList(resources []any, total, startIndex, perPage int) ListResponse {
	if resources == nil {
		resources = []any{}
	}
	return ListResponse{
		Schemas: []string{SchemaList}, TotalResults: total,
		StartIndex: startIndex, ItemsPerPage: perPage, Resources: resources,
	}
}

// Error is the SCIM error envelope (status carried as a string per RFC 7644).
type Error struct {
	Schemas  []string `json:"schemas"`
	Detail   string   `json:"detail"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
}

// NewError builds a SCIM error for an HTTP status (scimType optional, e.g.
// "uniqueness", "invalidValue", "invalidSyntax").
func NewError(httpStatus int, scimType, detail string) Error {
	return Error{Schemas: []string{SchemaError}, Detail: detail, Status: itoa(httpStatus), ScimType: scimType}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
