// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/a2a"
)

// ARCH-009: with no broker attached the session-start endpoint reports
// unavailable rather than panicking; with one attached and a valid body it is
// reachable (the broker enforces tenant/agent validity).
func TestStartA2ASessionUnavailableWithoutBroker(t *testing.T) {
	s := &Server{} // no broker
	req := httptest.NewRequest("POST", "/v1/a2a/sessions", strings.NewReader(`{"responder_agent":"a","initiator_agent":"b","mode":"icmp"}`))
	err := s.handleStartA2ASession(httptest.NewRecorder(), req)
	if err == nil {
		t.Fatal("expected an error when the broker is not enabled")
	}
}

// With a broker attached, WithA2ABroker stores it (the wiring seam).
func TestWithA2ABroker(t *testing.T) {
	s := (&Server{}).WithA2ABroker(a2a.NewBroker())
	if s.a2aBroker == nil {
		t.Fatal("WithA2ABroker did not attach the broker")
	}
	if s.a2aMesh == nil {
		t.Fatal("WithA2ABroker did not attach the mesh scheduler")
	}
}

func TestStartA2AMeshUnavailableWithoutBroker(t *testing.T) {
	s := &Server{} // no broker
	req := httptest.NewRequest("POST", "/v1/a2a/mesh", strings.NewReader(`{"agents":[{"agent_id":"a","site":"one"},{"agent_id":"b","site":"two"}]}`))
	err := s.handleStartA2AMesh(httptest.NewRecorder(), req)
	if err == nil {
		t.Fatal("expected an error when the mesh scheduler is not enabled")
	}
}
