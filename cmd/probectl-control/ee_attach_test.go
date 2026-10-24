// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
	at := func(marker string) int {
		t.Helper()
		i := strings.Index(text, marker)
		if i < 0 {
			t.Fatalf("expected marker %q in ee_attach.go", marker)
		}
		return i
	}
	stopMode := at("} else if err := siloStartupPreconditions(ctx, pool, prov, len(ch.Readers) > 0, log); err != nil {")
	quarantineMode := at("if supervisor, err = bootSiloQuarantine(ctx, cfg, pool, prov, planes, registry, len(ch.Readers) > 0, log); err != nil {")
	publish := at("tenancy.SetRouter(router) // Postgres search_path")
	// Both modes settle every tenant's preconditions before the router is
	// published: stop mode refuses startup, quarantine mode (D-62) enters each
	// failing tenant into the registry the router refuses.
	if publish < stopMode || publish < quarantineMode {
		t.Fatalf("silo router is published before the startup preconditions; stop=%d quarantine=%d publish=%d", stopMode, quarantineMode, publish)
	}
	if !strings.Contains(text, "router := silo.NewRouter(pool, planes, 0).WithQuarantine(registry)") {
		t.Fatal("the silo router must refuse quarantined tenants (D-62)")
	}
	// The supervisor's tenant-chain audit resolves the tenant's schema
	// through the router, so it starts only once the router is published.
	if start := at("supervisor.Start(ctx)"); start < publish {
		t.Fatalf("quarantine supervisor starts before the router is published; start=%d publish=%d", start, publish)
	}
	// ARCH-001 then DPR-323, inside the stop-mode preconditions.
	catch := at("if err := siloCatchUpAll(ctx, pool, prov, log); err != nil")
	readerCatch := at("if err := siloReaderCatchUpAll(ctx, pool, prov, scoped, log); err != nil")
	if readerCatch < catch {
		t.Fatalf("reader-scope catch-up runs before the schema catch-up; catch=%d reader=%d", catch, readerCatch)
	}
	// DPR-324: a tenant pinned to a missing plane refuses startup before
	// anything is routed or caught up (stop mode).
	preflight := at("if err := siloResidencyPreflight(ctx, pool, silo.PlaneNames(planes)); err != nil")
	if preflight > stopMode || preflight > publish {
		t.Fatalf("the residency preflight must run before the catch-ups and router publication; preflight=%d stop=%d publish=%d", preflight, stopMode, publish)
	}
	if strings.Index(text, "ch.Readers = siloReaderScopes(") > strings.Index(text, "prov, err := newSiloProvisioner(") {
		t.Fatal("the provisioner is built before the stores' reader scopes are attached, so new silos would get no reader scope")
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
		"govern.GatePolicyWrites(govern.NewPolicyStore(pool), writeCapability)",
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
