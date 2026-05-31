// Package control implements the netctl control-plane HTTP API server: its
// lifecycle, middleware chain (request-id + request-scoped logging, security
// headers, access logging, panic recovery), the health/readiness/version/OpenAPI
// endpoints, the domain-error→HTTP mapping, and graceful shutdown (S1).
//
// Handlers are thin: they return domain errors (internal/apierror) and the
// adapter maps them to status codes. Every request carries a context capable of
// holding tenant identity, which S2 resolves (internal/tenancy). Versioned
// resource endpoints under /v1 are added by later sprints (S9+).
package control
