// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
)

// fakeReaderLane records what installCHReaderPolicy asked of a store.
type fakeReaderLane struct {
	ensured, verified string
	ensureErr         error
	verifyErr         error
}

func (f *fakeReaderLane) EnsureReaderRowPolicy(_ context.Context, user string) error {
	f.ensured = user
	return f.ensureErr
}

func (f *fakeReaderLane) VerifyReaderIsolation(_ context.Context, user string) error {
	f.verified = user
	return f.verifyErr
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// writeCredential writes one owner-only basic-auth credential file.
func writeCredential(t *testing.T, username, password string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), username+".json")
	body := `{"username":"` + username + `","password":"` + password + `"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readerFactory(t *testing.T, username string) *crypto.BasicAuthClientFactory {
	t.Helper()
	f, err := crypto.LoadBasicAuthClientFactory(writeCredential(t, username, "reader-password-ci-only"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func scopedSpec(t *testing.T, readerUser string) chReaderSpec {
	return chReaderSpec{
		scopingOn: true, readerUser: readerUser, storeURL: "https://clickhouse.example:8443",
		plane: "otelstore", finding: "RED-001", readerAuth: readerFactory(t, "probectl_reader"),
	}
}

func TestInstallCHReaderPolicyRequiresReaderUser(t *testing.T) {
	enableCalled := false
	spec := scopedSpec(t, " \t")
	err := installCHReaderPolicy(spec, discardLog(), func(*http.Client) (chReaderLane, bool) {
		enableCalled = true
		return &fakeReaderLane{ensureErr: errors.New("ensure must not be called with a blank reader user")}, true
	})
	if err == nil {
		t.Fatal("blank reader user should fail closed")
	}
	if !strings.Contains(err.Error(), "reader user is unset") || !strings.Contains(err.Error(), "RED-001") {
		t.Fatalf("error %q missing fail-closed context", err)
	}
	if !enableCalled {
		t.Fatal("ClickHouse-backed lane should be detected before refusing the blank reader")
	}
}

func TestInstallCHReaderPolicySkipsNonClickHouseStore(t *testing.T) {
	// A memory lane with scoping on needs neither a reader user nor a reader
	// credential: there is no ClickHouse read to scope.
	spec := chReaderSpec{scopingOn: true, plane: "pathstore", finding: "RED-001"}
	if err := installCHReaderPolicy(spec, discardLog(), func(*http.Client) (chReaderLane, bool) {
		return nil, false
	}); err != nil {
		t.Fatalf("memory/non-ClickHouse store should be a no-op: %v", err)
	}
}

// DPR-285: the store is handed the reader client, the policy binds the
// trimmed reader user, and the live isolation proof runs on that same user.
func TestInstallCHReaderPolicyAttachesReaderInstallsAndVerifies(t *testing.T) {
	lane := &fakeReaderLane{}
	var gotClient *http.Client
	err := installCHReaderPolicy(scopedSpec(t, " probectl_reader "), discardLog(), func(reader *http.Client) (chReaderLane, bool) {
		gotClient = reader
		return lane, true
	})
	if err != nil {
		t.Fatalf("install policy: %v", err)
	}
	if gotClient == nil {
		t.Fatal("the store was not handed a reader client: its tenant reads would have no reader lane")
	}
	if lane.ensured != "probectl_reader" || lane.verified != "probectl_reader" {
		t.Fatalf("ensured %q / verified %q, want trimmed probectl_reader for both", lane.ensured, lane.verified)
	}
}

func TestInstallCHReaderPolicyPropagatesInstallError(t *testing.T) {
	installErr := errors.New("ddl denied")
	lane := &fakeReaderLane{ensureErr: installErr}
	err := installCHReaderPolicy(scopedSpec(t, "probectl_reader"), discardLog(), func(*http.Client) (chReaderLane, bool) {
		return lane, true
	})
	if !errors.Is(err, installErr) {
		t.Fatalf("install error = %v, want %v", err, installErr)
	}
	if lane.verified != "" {
		t.Fatal("verification ran after a failed policy install")
	}
}

// DPR-285: a failed live isolation proof refuses to start.
func TestInstallCHReaderPolicyRefusesWhenIsolationProofFails(t *testing.T) {
	proofErr := errors.New("reader sees foreign rows")
	err := installCHReaderPolicy(scopedSpec(t, "probectl_reader"), discardLog(), func(*http.Client) (chReaderLane, bool) {
		return &fakeReaderLane{verifyErr: proofErr}, true
	})
	if !errors.Is(err, proofErr) || !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("err = %v, want the isolation proof failure to refuse start", err)
	}
}

// DPR-285: the reader credential must authenticate as the user the policy
// binds; otherwise the policy guards a login the reads never use.
func TestInstallCHReaderPolicyRefusesReaderUsernameMismatch(t *testing.T) {
	lane := &fakeReaderLane{}
	err := installCHReaderPolicy(scopedSpec(t, "probectl_other_reader"), discardLog(), func(*http.Client) (chReaderLane, bool) {
		return lane, true
	})
	if err == nil || !strings.Contains(err.Error(), `authenticates as "probectl_reader" but the row policy binds "probectl_other_reader"`) {
		t.Fatalf("err = %v, want a username mismatch refusal", err)
	}
	if lane.ensured != "" {
		t.Fatal("a mismatched reader must be refused before any DDL")
	}
}

// DPR-285: scoping on a ClickHouse lane with no reader credential hands the
// store no reader client, and the live proof (here faked as the store would
// answer, chclient.ErrReaderRequired) refuses to start. Never the control login.
func TestInstallCHReaderPolicyWithoutReaderCredentialHandsNoClient(t *testing.T) {
	spec := scopedSpec(t, "probectl_reader")
	spec.readerAuth = nil
	var handed *http.Client
	err := installCHReaderPolicy(spec, discardLog(), func(reader *http.Client) (chReaderLane, bool) {
		handed = reader
		return &fakeReaderLane{verifyErr: errors.New("no reader connection is attached")}, true
	})
	if handed != nil {
		t.Fatal("a reader client was built without a reader credential")
	}
	if err == nil {
		t.Fatal("a scoped lane without a reader credential must refuse to start")
	}
}

func TestClickHouseReaderFactoryRefusesTheControlLogin(t *testing.T) {
	control := readerFactory(t, "probectl")
	cfg := &config.Config{
		OTelStoreMode: "clickhouse", ClickHouseReaderBasicAuthFile: writeCredential(t, "probectl", "control-password-ci-only"),
	}
	if _, err := clickHouseReaderFactory(cfg, control); err == nil || !strings.Contains(err.Error(), "control login") {
		t.Fatalf("err = %v, want the control login refused as the reader", err)
	}
	cfg.ClickHouseReaderBasicAuthFile = writeCredential(t, "probectl_reader", "reader-password-ci-only")
	reader, err := clickHouseReaderFactory(cfg, control)
	if err != nil || reader.Username() != "probectl_reader" {
		t.Fatalf("reader = %v, err = %v", reader, err)
	}
}

// DPR-323: the reader reaches each residency plane with that plane's reader
// credential, which must be the login the per-tenant row policies bind and
// never the plane's control login.
func TestClickHouseReaderFactoryPinsEachPlaneReader(t *testing.T) {
	const planes = "eu=https://ch-eu.example:8443"
	controlFor := func(t *testing.T, euControlUser string) *crypto.BasicAuthClientFactory {
		control := readerFactory(t, "probectl")
		if err := control.WithOriginCredentialFile("https://ch-eu.example:8443", writeCredential(t, euControlUser, "eu-control-ci-only")); err != nil {
			t.Fatal(err)
		}
		return control
	}
	cfg := func(t *testing.T, euReaderUser string) *config.Config {
		return &config.Config{
			OTelStoreMode: "clickhouse", ClickHouseReaderBasicAuthFile: writeCredential(t, "probectl_reader", "reader-password-ci-only"),
			DataPlanes: planes, DataPlaneReaderBasicAuthFiles: map[string]string{"eu": writeCredential(t, euReaderUser, "eu-reader-ci-only")},
		}
	}
	reader, err := clickHouseReaderFactory(cfg(t, "probectl_reader"), controlFor(t, "probectl_eu"))
	if err != nil {
		t.Fatal(err)
	}
	if user, ok := reader.OriginUsername("https://ch-eu.example:8443", ""); !ok || user != "probectl_reader" {
		t.Fatalf("eu plane reader = %q, %v; want the pinned probectl_reader credential", user, ok)
	}
	if _, err := clickHouseReaderFactory(cfg(t, "someone_else"), controlFor(t, "probectl_eu")); err == nil || !strings.Contains(err.Error(), "every plane's reader must be the same login") {
		t.Fatalf("err = %v, want a plane reader with another login refused", err)
	}
	if _, err := clickHouseReaderFactory(cfg(t, "probectl_reader"), controlFor(t, "probectl_reader")); err == nil || !strings.Contains(err.Error(), "that plane's control login") {
		t.Fatalf("err = %v, want the plane's control login refused as its reader", err)
	}
}

func TestClickHouseReaderClientDropsURLUserinfo(t *testing.T) {
	f := readerFactory(t, "probectl_reader")
	// A loopback dev URL may carry the control login as userinfo; the reader
	// client must be pinned to the bare origin, not refuse or reuse it.
	if _, err := clickHouseReaderClient(f, "http://probectl:control@127.0.0.1:8123"); err != nil {
		t.Fatalf("reader client over a userinfo URL: %v", err)
	}
	if c, err := clickHouseReaderClient(nil, "https://clickhouse.example:8443"); c != nil || err != nil {
		t.Fatalf("nil factory = (%v, %v), want no client", c, err)
	}
	if _, err := clickHouseReaderClient(f, ""); err == nil {
		t.Fatal("a reader credential without an endpoint must refuse")
	}
}
