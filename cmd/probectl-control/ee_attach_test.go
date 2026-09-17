// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

func TestProviderIRAdmissionRequiresSignedWORM(t *testing.T) {
	err := attachProviderIRDurability(context.Background(), nil, nil)
	if err == nil || !strings.Contains(
		err.Error(),
		"requires signed WORM audit export",
	) {
		t.Fatalf("nil-WORM provider IR admission error = %v, want fail-closed", err)
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

func TestLicenseReadOnlyMutationCapabilityInstalledOnceAtEEAttach(t *testing.T) {
	src, err := os.ReadFile("ee_attach.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if got := strings.Count(text, "lic.WriteCapability()"); got != 1 {
		t.Fatalf("dynamic write capability constructors in ee_attach.go = %d, want exactly one", got)
	}
	for _, wiring := range []string{
		"tenantcrypto.GateKeyManagerWrites(tenantkeys.NewManager(ring), writeCapability)",
		"remediation.GateServiceWrites(remed, writeCapability)",
	} {
		if !strings.Contains(text, wiring) {
			t.Fatalf("ee attach seam is missing shared read-only mutation wiring %q", wiring)
		}
	}
}

func TestEERoutedStoresPropagateOperationContext(t *testing.T) {
	src, err := os.ReadFile("ee_attach.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	if strings.Contains(text, "router.TargetsFor(context.Background(), tenantID)") {
		t.Fatal("EE target routing discards the caller's operation context")
	}
	if got := strings.Count(text, "router.TargetsFor(ctx, tenantID)"); got != 5 {
		t.Fatalf("context-aware EE target adapters = %d, want all five stores", got)
	}
}
