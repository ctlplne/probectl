// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenantlife"
)

// TestExtendWriteDeadlineSurvivesWriteTimeout is the WEB-04 regression: the
// server's absolute WriteTimeout reset any response not fully delivered within
// the (default 15s) window — aborting path discovery, remote-model AI answers,
// and large/slow exports mid-flight. extendWriteDeadline lifts that deadline for
// a long-running response. The control (no extension) proves the WriteTimeout is
// real and that the extension is what saves the response.
func TestExtendWriteDeadlineSurvivesWriteTimeout(t *testing.T) {
	const body = "RESPONSE-BODY-OK"
	mux := http.NewServeMux()
	// Long handler: starts work, extends the deadline, then responds after the
	// short global WriteTimeout would have fired.
	mux.HandleFunc("/extend", func(w http.ResponseWriter, _ *http.Request) {
		extendWriteDeadline(w, 5*time.Second)
		time.Sleep(600 * time.Millisecond)
		_, _ = io.WriteString(w, body)
	})
	// Control handler: same timing, no extension — must be cut off at the
	// WriteTimeout.
	mux.HandleFunc("/plain", func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(600 * time.Millisecond)
		_, _ = io.WriteString(w, body)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// Route through the SAME access-log wrapper production uses: every request's
	// ResponseWriter is a *statusRecorder, so http.NewResponseController must be
	// able to Unwrap() it to reach the socket. Testing on a bare mux hid the
	// original no-op (the recorder had no Unwrap) — WEB-04 reopen.
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&statusRecorder{ResponseWriter: w}, r)
	})
	srv := &http.Server{Handler: wrapped, WriteTimeout: 200 * time.Millisecond}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	base := "http://" + ln.Addr().String()

	get := func(path string) (string, error) {
		resp, err := http.Get(base + path)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}

	// The extended response is delivered in full despite exceeding the 200ms
	// WriteTimeout.
	got, err := get("/extend")
	if err != nil || got != body {
		t.Fatalf("extended long response did not complete: body=%q err=%v (WriteTimeout reset a response extendWriteDeadline should have protected)", got, err)
	}
	// The un-extended response is cut off at the WriteTimeout (truncated body or
	// a read/connection error) — proving the deadline is real.
	if got, err := get("/plain"); err == nil && strings.Contains(got, body) {
		t.Fatalf("un-extended long response unexpectedly completed in full (%q); the WriteTimeout is not enforced, so the test proves nothing", got)
	}
}

// slowLifecycle is a lifecycle engine whose erasures take longer than the
// server's write timeout, as a real erasure waiting on every store does.
type slowLifecycle struct {
	fakeTenantLifecycle
	delay time.Duration
}

func (s *slowLifecycle) Erase(_ context.Context, tenantID, slug, actor string) (tenantlife.Attestation, error) {
	time.Sleep(s.delay)
	return tenantlife.Attestation{TenantID: tenantID, TenantSlug: slug, Actor: actor, Complete: true, ReportSHA256: "slow-receipt"}, nil
}

func (s *slowLifecycle) EraseSubject(_ context.Context, tenantID, _, actor, _ string) (tenantlife.SubjectErasureReport, error) {
	time.Sleep(s.delay)
	return tenantlife.SubjectErasureReport{TenantID: tenantID, Actor: actor, Complete: true, ReportSHA256: "slow-receipt"}, nil
}

// serveWithWriteTimeout serves h on a loopback listener whose server resets
// any response not written within timeout, and returns its base URL.
func serveWithWriteTimeout(t *testing.T, h http.Handler, timeout time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h, WriteTimeout: timeout}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

// TestSubjectErasureResponseOutlivesTheWriteTimeout (WEB-04): an erasure waits
// on every store's synchronous delete, so it outlives the server's short global
// write timeout. Without its own budget the server reset the response while
// the erasure ran on, and the caller never received the receipt it erased the
// data for.
func TestSubjectErasureResponseOutlivesTheWriteTimeout(t *testing.T) {
	srv := testServer(fakePinger{})
	srv.tenantLife = &slowLifecycle{delay: 600 * time.Millisecond}
	base := serveWithWriteTimeout(t, srv.Handler(), 200*time.Millisecond)
	resp, err := http.Post(base+"/v1/lifecycle/subjects/erase", "application/json",
		strings.NewReader(`{"subject":"alice@example.com","confirm":"alice@example.com","reason":"dsar"}`))
	if err != nil {
		t.Fatalf("the subject erasure's response was reset: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"report_sha256":"slow-receipt"`) {
		t.Fatalf("the subject erasure's receipt did not arrive: %d %q %v", resp.StatusCode, body, err)
	}
}
