package control

import "regexp"

// uuidRe validates tenant UUIDs supplied out-of-band: the dev-auth-mode
// X-Probectl-Tenant override (auth.go) and the SSO ?tenant= selector. Real
// authentication (S18) resolves the tenant from the session principal; every
// /v1 handler is tenant-scoped via internal/tenancy + Postgres RLS regardless.
var uuidRe = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
