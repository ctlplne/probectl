// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package silo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/store/chclient"
)

// fakeReaderScope records every reader-scope call against one server.
type fakeReaderScope struct {
	server    string
	ch        *compCH // when set, Ensure requires every plane's tables to exist
	calls     []string
	verifyErr error
}

func (f *fakeReaderScope) Endpoint(base string) string {
	if base != "" {
		return base
	}
	return f.server
}

func (f *fakeReaderScope) Ensure(_ context.Context, base, db string) error {
	if f.ch != nil && len(f.ch.live()) != 5 {
		return errors.New("reader scope ran before every plane's tables existed")
	}
	f.calls = append(f.calls, "ensure "+f.Endpoint(base)+" "+db)
	return nil
}

func (f *fakeReaderScope) Verify(_ context.Context, base, db string) error {
	f.calls = append(f.calls, "verify "+f.Endpoint(base)+" "+db)
	return f.verifyErr
}

func (f *fakeReaderScope) Revoke(_ context.Context, base, db string) error {
	if f.ch != nil && len(f.ch.live()) != 5 {
		return errors.New("reader grants revoked after the databases they name were dropped")
	}
	f.calls = append(f.calls, "revoke "+f.Endpoint(base)+" "+db)
	return nil
}

func readerProvisioner(ch *compCH, planes map[string]DataPlane, readers ...ReaderScope) *Provisioner {
	return NewProvisioner(nil, CHPlanes{
		Flows: compFlow{ch}, Paths: compPath{ch}, EBPF: compEBPF{ch}, Otel: compOtel{ch}, Endpoint: compEndpoint{ch},
		Readers: readers,
	}, planes, 30, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// DPR-323: provisioning puts the per-tenant database under the reader scope
// and proves it, after every plane's tables exist, once per ClickHouse server,
// on the tenant's residency plane.
func TestProvisionScopesTheReaderOncePerServerAfterEveryPlane(t *testing.T) {
	ch := newCompCH()
	pooledA := &fakeReaderScope{server: "https://ch-pooled:8443", ch: ch}
	pooledB := &fakeReaderScope{server: "https://ch-pooled:8443", ch: ch} // a second store on the same server
	other := &fakeReaderScope{server: "https://ch-other:8443", ch: ch}
	p := readerProvisioner(ch, nil, pooledA, pooledB, other)
	if err := p.provisionCH(context.Background(), "tenant-a", ""); err != nil {
		t.Fatal(err)
	}
	db := CHDatabase("tenant-a")
	if got, want := strings.Join(pooledA.calls, ";"), "ensure https://ch-pooled:8443 "+db+";verify https://ch-pooled:8443 "+db; got != want {
		t.Fatalf("pooled server reader scope calls = %q, want %q", got, want)
	}
	if len(pooledB.calls) != 0 {
		t.Fatalf("a second store on the same server re-scoped it: %q", pooledB.calls)
	}
	if got, want := strings.Join(other.calls, ";"), "ensure https://ch-other:8443 "+db+";verify https://ch-other:8443 "+db; got != want {
		t.Fatalf("second server reader scope calls = %q, want %q", got, want)
	}

	eu := &fakeReaderScope{server: "https://ch-pooled:8443"}
	p = readerProvisioner(newCompCH(), map[string]DataPlane{"eu": {Name: "eu", CHURL: "https://ch-eu:8443"}}, eu)
	if err := p.provisionCH(context.Background(), "tenant-b", "eu"); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(eu.calls, ";"), "ensure https://ch-eu:8443 "+CHDatabase("tenant-b")+";verify https://ch-eu:8443 "+CHDatabase("tenant-b"); got != want {
		t.Fatalf("residency reader scope calls = %q, want %q", got, want)
	}
}

// A per-tenant database whose reader scope cannot be proven is not left
// behind: the scope is withdrawn and every plane's database compensated.
func TestProvisionWithdrawsAnUnprovenReaderScope(t *testing.T) {
	ch := newCompCH()
	r := &fakeReaderScope{server: "https://ch:8443", verifyErr: errors.New("the reader reads rows of another tenant")}
	p := readerProvisioner(ch, nil, r)
	err := p.provisionCH(context.Background(), "tenant-a", "")
	if err == nil || !strings.Contains(err.Error(), "reader scope") || !strings.Contains(err.Error(), "another tenant") {
		t.Fatalf("provision err = %v, want the reader scope failure", err)
	}
	if live := ch.live(); len(live) != 0 {
		t.Fatalf("databases survived an unproven reader scope: %v", live)
	}
	if got := r.calls[len(r.calls)-1]; !strings.HasPrefix(got, "revoke ") {
		t.Fatalf("the unproven scope was not withdrawn; calls %q", r.calls)
	}
}

func TestTeardownRevokesTheReaderBeforeDroppingDatabases(t *testing.T) {
	ch := newCompCH()
	r := &fakeReaderScope{server: "https://ch:8443"}
	p := readerProvisioner(ch, nil, r)
	if err := p.provisionCH(context.Background(), "tenant-a", ""); err != nil {
		t.Fatal(err)
	}
	r.ch = ch // the revoke must still see every database
	r.calls = nil
	if err := p.teardownCH(context.Background(), "tenant-a", ""); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 1 || !strings.HasPrefix(r.calls[0], "revoke ") {
		t.Fatalf("teardown reader calls = %q, want one revoke", r.calls)
	}
	if live := ch.live(); len(live) != 0 {
		t.Fatalf("teardown left %v", live)
	}
}

func TestCatchUpReaderScopeProvesExistingSilos(t *testing.T) {
	r := &fakeReaderScope{server: "https://ch:8443"}
	p := readerProvisioner(newCompCH(), map[string]DataPlane{"eu": {Name: "eu", CHURL: "https://ch-eu:8443"}}, r)
	if err := p.CatchUpReaderScope(context.Background(), "tenant-a", "eu"); err != nil {
		t.Fatal(err)
	}
	db := CHDatabase("tenant-a")
	if got, want := strings.Join(r.calls, ";"), "ensure https://ch-eu:8443 "+db+";verify https://ch-eu:8443 "+db; got != want {
		t.Fatalf("catch-up calls = %q, want %q", got, want)
	}
	r.calls, r.verifyErr = nil, errors.New("reader sees foreign rows")
	err := p.CatchUpReaderScope(context.Background(), "tenant-a", "eu")
	if err == nil || !strings.Contains(err.Error(), "tenant-a") || !strings.Contains(err.Error(), "foreign rows") {
		t.Fatalf("catch-up err = %v, want a tenant-named failure", err)
	}
	// A residency dropped from the configuration is scoped where the router
	// now sends the tenant: the default plane.
	r.calls, r.verifyErr = nil, nil
	if err := p.CatchUpReaderScope(context.Background(), "tenant-a", "mars"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r.calls, ";"); got != "ensure https://ch:8443 "+db+";verify https://ch:8443 "+db {
		t.Fatalf("catch-up of an unconfigured residency = %q, want the default plane", got)
	}
	// No scoped store: nothing runs as the reader, nothing to scope.
	if err := readerProvisioner(newCompCH(), nil).CatchUpReaderScope(context.Background(), "tenant-a", ""); err != nil {
		t.Fatal(err)
	}
}

// DPR-326: at boot a live tenant's reader scope is withdrawn only when the
// proof definitively shows it unsafe. A proof that could not run (a timeout,
// a canceled startup, a network blip) leaves the grants in place for the
// replicas already serving the tenant; this process just refuses to start.
func TestCatchUpWithdrawsTheScopeOnlyOnADefinitiveUnsafeResult(t *testing.T) {
	for _, tc := range []struct {
		name         string
		verifyErr    error
		wantWithdraw bool
	}{
		{name: "a timeout leaves the scope", verifyErr: fmt.Errorf("reader credential cannot query ClickHouse: %w", context.DeadlineExceeded)},
		{name: "a canceled startup leaves the scope", verifyErr: context.Canceled},
		{name: "a transport error leaves the scope", verifyErr: errors.New("dial tcp 10.0.0.9:8443: connect: connection refused")},
		{name: "foreign rows withdraw it", verifyErr: fmt.Errorf("pathstore: %w: reads rows of another tenant", chclient.ErrReaderUnsafe), wantWithdraw: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &fakeReaderScope{server: "https://ch:8443", verifyErr: tc.verifyErr}
			p := readerProvisioner(newCompCH(), nil, r)
			if err := p.CatchUpReaderScope(context.Background(), "tenant-a", ""); !errors.Is(err, tc.verifyErr) {
				t.Fatalf("catch-up err = %v, want it to carry %v (startup refused)", err, tc.verifyErr)
			}
			withdrew := strings.HasPrefix(r.calls[len(r.calls)-1], "revoke ")
			if withdrew != tc.wantWithdraw {
				t.Fatalf("withdrew the live scope = %v, want %v (calls %q)", withdrew, tc.wantWithdraw, r.calls)
			}
		})
	}
}

// DPR-327: a residency plane needs a reader credential exactly when a tenant
// lives on it. Provisioning or catching up a tenant there without one is
// refused before any reader scope is touched, and the refusal is the check's.
func TestReaderScopeRefusesAPlaneTheReaderCannotReach(t *testing.T) {
	planes := map[string]DataPlane{"eu": {Name: "eu", CHURL: "https://ch-eu:8443"}}
	gap := errors.New("add eu=/path to PROBECTL_DATAPLANE_READER_BASIC_AUTH_FILES")
	checked := map[string]int{}
	check := func(residency string) error {
		checked[residency]++
		if residency == "eu" {
			return gap
		}
		return nil
	}
	ch := newCompCH()
	r := &fakeReaderScope{server: "https://ch:8443"}
	p := readerProvisioner(ch, planes, r).WithReaderPlaneCheck(check)
	if err := p.CatchUpReaderScope(context.Background(), "tenant-eu", "eu"); !errors.Is(err, gap) {
		t.Fatalf("catch-up on an unreachable plane = %v, want the check's refusal", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("the reader scope was touched on a plane the reader cannot reach: %q", r.calls)
	}
	if err := p.provisionCH(context.Background(), "tenant-eu", "eu"); !errors.Is(err, gap) {
		t.Fatalf("provisioning on an unreachable plane = %v, want the check's refusal", err)
	}
	if live := ch.live(); len(live) != 0 {
		t.Fatalf("a refused provisioning left %v", live)
	}
	// The default plane is the reader's own: never checked, never refused.
	if err := p.CatchUpReaderScope(context.Background(), "tenant-home", ""); err != nil || checked[""] != 0 {
		t.Fatalf("default-plane catch-up = %v (checked %d times)", err, checked[""])
	}
}
