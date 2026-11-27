// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
)

const verdictRoutedHTTPSAddress = "192.0.2.2"

func TestIncidentVerdictRoutedHTTPSNamesOnlyItsProvider(t *testing.T) {
	if os.Getenv("PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB") != "1" {
		testsupport.SkipOptIn(t, "PROBECTL_TEST_REQUIRE_DEPENDENCY_LAB", "isolated Linux router and probe namespaces")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the required routed HTTPS proof needs namespace privileges")
	}
	proveIncidentVerdictRealHTTPS(t, "aws", startVerdictRoutedHTTPSLab)
}

func startVerdictRoutedHTTPSLab(t *testing.T, code int) verdictHTTPSLab {
	t.Helper()
	network := newDependencyPhysicalNetwork(t)
	// Admit a second independent vantage through the source router. Both
	// routes stay in the isolated lab and reach the same configured origin.
	enableDependencySecondVantage(t, network)
	listener, err := verdictRoutedHTTPSListener(network.child)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ca, err := crypto.GenerateCA("probectl-routed-verdict-fixture", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.IssueServerCert("routed-verdict", []string{verdictRoutedHTTPSAddress}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	config, err := crypto.ServerTLSConfig(verdictEvidenceFile(t, dir, "origin.crt", cert), verdictEvidenceFile(t, dir, "origin.key", key))
	if err != nil {
		t.Fatal(err)
	}
	var seen sync.Map
	handler := overlappingVerdictHTTPHandler(code, func(r *http.Request) bool {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || (host != "10.250.0.2" && host != "10.250.2.2") {
			return false
		}
		_, duplicate := seen.LoadOrStore(host, struct{}{})
		return !duplicate
	})
	target := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}, TLS: config}
	target.StartTLS()
	t.Cleanup(target.Close)
	names := [2]string{network.source, network.other}
	outputs := [2]string{filepath.Join(dir, "source.json"), filepath.Join(dir, "other.json")}
	return verdictHTTPSLab{
		url: target.URL, certificate: ca.CertPEM(),
		collect: func(ctx context.Context, index int, definition testspec.ExecutableDefinition) (canary.Result, error) {
			return collectRoutedVerdictHTTP(ctx, names[index], outputs[index], definition)
		},
	}
}

// Open the listener on the lab's child interface. Accepted sockets retain that
// namespace while the test process keeps its original database and mTLS lanes.
func verdictRoutedHTTPSListener(namespace string) (net.Listener, error) {
	return openVerdictLabSocket(namespace, func() (net.Listener, error) {
		return net.Listen("tcp4", net.JoinHostPort(verdictRoutedHTTPSAddress, "0"))
	})
}

func openVerdictLabSocket[T io.Closer](namespace string, open func() (T, error)) (T, error) {
	type outcome struct {
		socket T
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		runtime.LockOSThread()
		unlock := true
		defer func() {
			if unlock {
				runtime.UnlockOSThread()
			}
		}()
		original, err := os.Open("/proc/thread-self/ns/net")
		if err != nil {
			finished <- outcome{err: err}
			return
		}
		defer original.Close()
		target, err := os.Open(filepath.Join("/run/netns", namespace))
		if err != nil {
			finished <- outcome{err: err}
			return
		}
		defer target.Close()
		if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			finished <- outcome{err: err}
			return
		}
		socket, err := open()
		if restoreErr := unix.Setns(int(original.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			if err == nil {
				_ = socket.Close()
			}
			// Retire the OS thread instead of returning it to the Go scheduler.
			unlock = false
			finished <- outcome{err: restoreErr}
			return
		}
		finished <- outcome{socket, err}
	}()
	result := <-finished
	return result.socket, result.err
}

type routedVerdictHTTPMeasurement struct {
	Result   canary.Result
	Response *canary.HTTPMeasurement
}

func collectRoutedVerdictHTTP(ctx context.Context, namespace, output string, definition testspec.ExecutableDefinition) (canary.Result, error) {
	body, err := json.Marshal(definition)
	if err != nil {
		return canary.Result{}, err
	}
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", namespace, os.Args[0], "-test.run=^TestRoutedVerdictHTTPProbeProcess$")
	cmd.Env = append(os.Environ(), "PROBECTL_TEST_ROUTED_VERDICT_PROBE="+string(body), "PROBECTL_TEST_ROUTED_VERDICT_OUTPUT="+output)
	if log, err := cmd.CombinedOutput(); err != nil {
		return canary.Result{}, fmt.Errorf("routed HTTPS probe: %w: %s", err, log)
	}
	body, err = os.ReadFile(output)
	if err != nil {
		return canary.Result{}, err
	}
	var received routedVerdictHTTPMeasurement
	if err := json.Unmarshal(body, &received); err != nil {
		return canary.Result{}, err
	}
	if received.Response == nil || received.Response.PeerAddress != netip.MustParseAddr(verdictRoutedHTTPSAddress) {
		return canary.Result{}, errors.New("the routed probe did not attest the configured socket peer")
	}
	received.Result.HTTP = received.Response
	return received.Result, nil
}

func TestRoutedVerdictHTTPProbeProcess(t *testing.T) {
	raw := os.Getenv("PROBECTL_TEST_ROUTED_VERDICT_PROBE")
	if raw == "" {
		return
	}
	var definition testspec.ExecutableDefinition
	if err := json.Unmarshal([]byte(raw), &definition); err != nil {
		t.Fatal(err)
	}
	canary.SetCAFileDir(filepath.Dir(definition.Params["ca_file"]))
	result, err := collectVerdictHTTP(t.Context(), definition)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(routedVerdictHTTPMeasurement{Result: result, Response: result.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("PROBECTL_TEST_ROUTED_VERDICT_OUTPUT"), body, 0600); err != nil {
		t.Fatal(err)
	}
}
