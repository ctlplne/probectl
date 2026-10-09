// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import (
	"context"
	"errors"
	"testing"
)

type fakeRouter struct {
	targets map[string]Targets
	err     error
	ns      []string
}

func (f fakeRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	return nil, nil
}

func (f fakeRouter) TargetsFor(_ context.Context, id string) (Targets, error) {
	if f.err != nil {
		return Targets{}, f.err
	}
	return f.targets[id], nil
}

func (f fakeRouter) BusNamespaces(context.Context) ([]string, error) { return f.ns, f.err }

func TestIsolationModelValidation(t *testing.T) {
	for _, ok := range []string{"", "pooled", "siloed", "hybrid"} {
		if !ValidIsolationModel(ok) {
			t.Errorf("%q must be valid", ok)
		}
	}
	for _, bad := range []string{"POOLED", "physical", "silo", "shared"} {
		if ValidIsolationModel(bad) {
			t.Errorf("%q must be invalid", bad)
		}
	}
}

func TestRouterDefaultIsPooled(t *testing.T) {
	SetRouter(nil) // reset to the default
	tg, err := CurrentRouter().TargetsFor(context.Background(), "any")
	if err != nil || tg.PGSchema != "" || tg.CHDatabase != "" || tg.BusNamespace != "" {
		t.Fatalf("default router must be pooled: %+v %v", tg, err)
	}
	ns, err := CurrentRouter().BusNamespaces(context.Background())
	if err != nil || len(ns) != 0 {
		t.Fatalf("default namespaces: %v %v", ns, err)
	}
}

// An agent cannot read the tenant registry, so it routes artifacts from the
// model its operator declared: a hybrid or siloed tenant's go under its silo
// namespace, everyone else's keep the standard prefix.
func TestDeclaredRouterRoutesArtifactsByTheDeclaredModel(t *testing.T) {
	const tenant = "3FA2BC00-0000-4000-8000-0000000000AA"
	for model, want := range map[IsolationModel]string{
		IsolationHybrid: "silo/3fa2bc00-0000-4000-8000-0000000000aa",
		IsolationSiloed: "silo/3fa2bc00-0000-4000-8000-0000000000aa",
		IsolationPooled: "",
		"":              "",
	} {
		tg, err := DeclaredRouter{Model: model}.TargetsFor(context.Background(), tenant)
		if err != nil || tg.ObjectPrefix != want || tg.BusNamespace != "" || tg.PGSchema != "" || tg.CHDatabase != "" {
			t.Errorf("declared %q: targets = %+v (%v), want object prefix %q and nothing else", model, tg, err, want)
		}
	}
}

// TestPGSchemaFailClosed is the S-T2 watch-out as a unit property: a routing
// ERROR must fail the query — a siloed tenant must never silently fall
// through to the pooled schema. And a malformed schema name is refused even
// if a router returns one.
func TestPGSchemaFailClosed(t *testing.T) {
	defer SetRouter(nil)

	SetRouter(fakeRouter{err: errors.New("registry down")})
	if _, err := pgSchemaFor(context.Background(), "t1"); err == nil {
		t.Fatal("a routing error must fail closed, not default to pooled")
	}

	SetRouter(fakeRouter{targets: map[string]Targets{
		"ok":  {Model: IsolationSiloed, PGSchema: "t_3fa2bc"},
		"bad": {Model: IsolationSiloed, PGSchema: `public"; DROP TABLE tenants; --`},
	}})
	if s, err := pgSchemaFor(context.Background(), "ok"); err != nil || s != "t_3fa2bc" {
		t.Fatalf("valid schema: %q %v", s, err)
	}
	if _, err := pgSchemaFor(context.Background(), "bad"); err == nil {
		t.Fatal("a malformed schema name must be refused")
	}
	// A pooled tenant routes to no schema, no error.
	if s, err := pgSchemaFor(context.Background(), "unknown"); err != nil || s != "" {
		t.Fatalf("pooled tenant: %q %v", s, err)
	}
}

// TestPooledRouterListsEveryActiveTenantLane (DPR-049): without the
// commercial router the pooled router still answers lane questions from the
// installed tenant lister, so strict-lane mode has a lane for every tenant.
func TestPooledRouterListsEveryActiveTenantLane(t *testing.T) {
	SetRouter(nil)
	t.Cleanup(func() { SetPooledNamespaceLister(nil) })
	if ns, err := CurrentRouter().BusNamespaces(context.Background()); err != nil || len(ns) != 0 {
		t.Fatalf("no lister: %v %v", ns, err)
	}
	SetPooledNamespaceLister(func(context.Context) (map[string]string, error) {
		return map[string]string{BusNamespaceFor("globex"): "id-g", BusNamespaceFor("acme"): "id-a"}, nil
	})
	ns, err := CurrentRouter().BusNamespaces(context.Background())
	if err != nil || len(ns) != 2 || ns[0] != "t-acme" || ns[1] != "t-globex" {
		t.Fatalf("namespaces = %v, %v", ns, err)
	}
	tenants, err := CurrentRouter().BusNamespaceTenants(context.Background())
	if err != nil || tenants["t-acme"] != "id-a" {
		t.Fatalf("tenants = %v, %v", tenants, err)
	}
}
