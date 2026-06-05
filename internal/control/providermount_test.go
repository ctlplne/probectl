package control

import (
	"net/http"
	"testing"
)

// The S-T1 mount seam from the core side: /provider/* is a plain 404 when no
// plane is attached (hidden-unlicensed — indistinguishable from any unknown
// path), and dispatches to the attached handler when a licensed build wires
// one. Core knows the plane only as an opaque http.Handler.
func TestProviderPlaneMountSeam(t *testing.T) {
	srv := testServer(fakePinger{})

	// Unattached: hidden.
	rec := do(srv, http.MethodGet, "/provider/v1/tenants")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unattached provider plane must 404: %d", rec.Code)
	}
	unknown := do(srv, http.MethodGet, "/no/such/path")
	if rec.Code != unknown.Code {
		t.Fatalf("hidden surface must be indistinguishable from an unknown path: %d vs %d", rec.Code, unknown.Code)
	}

	// Attached (order-independent: AFTER New): dispatched.
	srv.WithProviderPlane(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	if rec = do(srv, http.MethodGet, "/provider/v1/tenants"); rec.Code != http.StatusTeapot {
		t.Fatalf("attached provider plane must dispatch: %d", rec.Code)
	}
	// Core routes are untouched by the mount.
	if rec = do(srv, http.MethodGet, "/v1/editions"); rec.Code != http.StatusOK {
		t.Fatalf("core routes after mount: %d", rec.Code)
	}
}
