// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build !probectl_core

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

type fakeSiloCatchUpper struct {
	fail map[string]error
	seen []string
}

func (f *fakeSiloCatchUpper) CatchUp(_ context.Context, tenantID string) error {
	f.seen = append(f.seen, tenantID)
	return f.fail[tenantID]
}

func TestSiloCatchUpTenantsFailsClosedOnAnyTenantFailure(t *testing.T) {
	prov := &fakeSiloCatchUpper{fail: map[string]error{"t-b": errors.New("missing table grant")}}
	err := siloCatchUpTenants(context.Background(), []string{"t-a", "t-b", "t-c"}, prov,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "t-b") || !strings.Contains(err.Error(), "missing table grant") {
		t.Fatalf("catch-up error = %v, want tenant-specific failure", err)
	}
	if got := strings.Join(prov.seen, ","); got != "t-a,t-b,t-c" {
		t.Fatalf("catch-up visited %q, want every tenant attempted for complete diagnostics", got)
	}
}

func TestEEAttachRunsSiloCatchUpBeforeRouterPublication(t *testing.T) {
	src, err := os.ReadFile("ee_attach.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	catch := strings.Index(text, "if err := siloCatchUpAll(ctx, pool, prov, log); err != nil")
	publish := strings.Index(text, "tenancy.SetRouter(router)")
	if catch < 0 || publish < 0 {
		t.Fatalf("expected catch-up and router publication markers in ee_attach.go")
	}
	if publish < catch {
		t.Fatalf("silo router is published before catch-up succeeds; catch=%d publish=%d", catch, publish)
	}
	if strings.Contains(text, "go func() {\n\t\t\tif err := siloCatchUpAll") {
		t.Fatal("silo catch-up must not run in a warning-only goroutine before startup readiness")
	}
}
