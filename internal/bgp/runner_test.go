// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bgp

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAnalyzerRunnerExecutesAndBridgesTenantBoundOutput(t *testing.T) {
	pub := &capturePublisher{}
	runner, err := NewAnalyzerRunner(pub, helperAnalyzerProcess("t1", "emit"), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	runner.stderr = io.Discard
	if err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pub.msgs) != 1 || tenantFromBGPKey(pub.msgs[0].key) != "t1" {
		t.Fatalf("published messages = %+v, want one tenant-t1 message", pub.msgs)
	}
}

func TestAnalyzerRunnerRejectsCrossTenantPayload(t *testing.T) {
	pub := &capturePublisher{}
	runner, err := NewAnalyzerRunner(pub, helperAnalyzerProcess("t2", "emit"), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	runner.stderr = io.Discard
	if err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pub.msgs) != 0 {
		t.Fatalf("cross-tenant analyzer output published %d messages, want zero", len(pub.msgs))
	}
}

func TestAnalyzerRunnerRestartBackoffIsBounded(t *testing.T) {
	pub := &capturePublisher{}
	process := helperAnalyzerProcess("t1", "crash")
	process.Restart = true
	runner, err := NewAnalyzerRunner(pub, process, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	runner.stderr = io.Discard
	runner.minBackoff = time.Second
	runner.maxBackoff = 4 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	var delays []time.Duration
	runner.wait = func(_ context.Context, d time.Duration) error {
		delays = append(delays, d)
		if len(delays) == 4 {
			cancel()
			return context.Canceled
		}
		return nil
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	if fmt.Sprint(delays) != fmt.Sprint(want) {
		t.Fatalf("backoff = %v, want bounded exponential %v", delays, want)
	}
}

func TestAnalyzerRunnerOneShotCrashReturnsWithoutRetry(t *testing.T) {
	pub := &capturePublisher{}
	runner, err := NewAnalyzerRunner(pub, helperAnalyzerProcess("t1", "crash"), discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	runner.stderr = io.Discard
	runner.wait = func(context.Context, time.Duration) error {
		t.Fatal("one-shot analyzer must not enter the live-process restart loop")
		return nil
	}
	if err := runner.Run(context.Background()); err == nil || !strings.Contains(err.Error(), "bgp analyzer process") {
		t.Fatalf("one-shot crash error = %v, want subprocess failure", err)
	}
}

func helperAnalyzerProcess(tenant, mode string) AnalyzerProcess {
	return AnalyzerProcess{
		TenantID:   tenant,
		Executable: os.Args[0],
		Args:       []string{"-test.run=TestAnalyzerRunnerHelperProcess", "--", mode},
		Env:        append(os.Environ(), "GO_WANT_BGP_ANALYZER_HELPER=1"),
	}
}

func TestAnalyzerRunnerHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_BGP_ANALYZER_HELPER") != "1" {
		return
	}
	mode := ""
	if i := strings.Index(strings.Join(os.Args, " "), "-- "); i >= 0 {
		mode = strings.TrimSpace(strings.Join(os.Args, " ")[i+3:])
	}
	if mode == "emit" {
		_, _ = fmt.Fprintln(os.Stdout, originChange)
		os.Exit(0)
	}
	if mode == "crash" {
		os.Exit(42)
	}
	os.Exit(2)
}
