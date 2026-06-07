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
