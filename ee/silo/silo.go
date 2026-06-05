// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
// See ee/doc.go for the boundary rules every ee/ file observes.

// Package silo implements the siloed and hybrid isolation models (S-T2,
// F52): per-tenant Postgres schemas, per-tenant ClickHouse databases
// (optionally on residency-pinned data planes), per-tenant bus topic
// namespaces, and per-tenant object-store namespaces — on top of, never
// instead of, the pooled defense-in-depth (RLS policies are recreated inside
// tenant schemas; bus messages stay tenant-keyed; reads stay tenant-scoped).
//
// The MODEL vocabulary is core (internal/tenancy); this package provides the
// Router that resolves tenants to their targets and the Provisioner that
// creates/catches-up/tears-down the isolated stores, both attached at the
// main.go seam when the license grants siloed_isolation.
package silo

import (
	"fmt"
	"sort"
	"strings"
)

// Naming: identifiers derive from the tenant UUID (stable, collision-free,
// never user input) except the bus namespace, which uses the slug (topics are
// operator-visible). All are validated by the consuming layer as well.

// SchemaName returns the tenant's Postgres schema: "t_<uuid sans dashes>".
func SchemaName(tenantID string) string {
	return "t_" + strings.ReplaceAll(strings.ToLower(tenantID), "-", "")
}

// CHDatabase returns the tenant's ClickHouse database name.
func CHDatabase(tenantID string) string {
	return "probectl_t_" + strings.ReplaceAll(strings.ToLower(tenantID), "-", "")
}

// BusNamespace returns the tenant's bus topic namespace: "t-<slug>".
func BusNamespace(slug string) string { return "t-" + slug }

// ObjectPrefix returns the tenant's object-store key namespace.
func ObjectPrefix(tenantID string) string { return "silo/" + strings.ToLower(tenantID) }

// DataPlane is a named residency target: where a pinned tenant's ClickHouse
// data lives. The default plane ("") is the deployment's shared endpoints.
// S-T2 pins the ClickHouse data plane; Postgres control state and the
// object/bus backends are NOT region-pinned yet (S-EE2 territory) — that
// honesty is part of the residency contract (docs/isolation.md).
type DataPlane struct {
	Name  string
	CHURL string
}

// ParseDataPlanes parses the PROBECTL_DATAPLANES value:
// "name=chURL[;name=chURL...]" (e.g. "eu=https://ch-eu:8123;us=https://ch-us:8123").
func ParseDataPlanes(raw string) (map[string]DataPlane, error) {
	planes := map[string]DataPlane{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return planes, nil
	}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, churl, ok := strings.Cut(part, "=")
		name, churl = strings.TrimSpace(name), strings.TrimSpace(churl)
		if !ok || name == "" || churl == "" {
			return nil, fmt.Errorf("silo: malformed data plane %q (want name=chURL)", part)
		}
		if !strings.HasPrefix(churl, "http://") && !strings.HasPrefix(churl, "https://") {
			return nil, fmt.Errorf("silo: data plane %q URL must be http(s)", name)
		}
		if _, dup := planes[name]; dup {
			return nil, fmt.Errorf("silo: duplicate data plane %q", name)
		}
		planes[name] = DataPlane{Name: name, CHURL: churl}
	}
	return planes, nil
}

// PlaneNames lists configured plane names, sorted (validation messages).
func PlaneNames(planes map[string]DataPlane) []string {
	out := make([]string, 0, len(planes))
	for n := range planes {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
