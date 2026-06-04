package control

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/secrets"
)

type fakeSecretsHealth struct{ snapshots []secrets.BackendHealth }

func (f fakeSecretsHealth) Health() []secrets.BackendHealth { return f.snapshots }

func TestSecretsHealthEndpoint(t *testing.T) {
	srv := testServer(fakePinger{}).WithSecrets(fakeSecretsHealth{snapshots: []secrets.BackendHealth{
		{Scheme: "env", Configured: true, Resolves: 4, CachedLeases: 0},
		{Scheme: "vault", Configured: true, Resolves: 7, Failures: 1,
			LastError: `secrets: backend unavailable: dial tcp: refused`,
			LastOK:    time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC), CachedLeases: 2},
	}})

	rec := do(srv, http.MethodGet, "/v1/secrets/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ResolverRunning bool                    `json:"resolver_running"`
		Backends        []secrets.BackendHealth `json:"backends"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.ResolverRunning || len(resp.Backends) != 2 {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Backends[1].Scheme != "vault" || resp.Backends[1].CachedLeases != 2 {
		t.Fatalf("vault snapshot = %+v", resp.Backends[1])
	}
	// The health payload must never contain secret material or full refs with
	// fragments — spot-check the serialized body for suspicious tokens.
	body := rec.Body.String()
	for _, leak := range []string{"#community", "s3cr3t", "password=", "Authorization"} {
		if strings.Contains(body, leak) {
			t.Fatalf("health body leaked %q: %s", leak, body)
		}
	}
}

func TestSecretsHealthHonestyWhenUnwired(t *testing.T) {
	srv := testServer(fakePinger{}) // no WithSecrets

	rec := do(srv, http.MethodGet, "/v1/secrets/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		ResolverRunning bool                    `json:"resolver_running"`
		Backends        []secrets.BackendHealth `json:"backends"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ResolverRunning || len(resp.Backends) != 0 {
		t.Fatalf("unwired resolver must report resolver_running=false and no backends, got %+v", resp)
	}
}
