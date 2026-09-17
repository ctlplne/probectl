// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/bus"
	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestSignalFromAlert(t *testing.T) {
	a := alert.Alert{
		TenantID: "t1", RuleName: "loss-high", RuleID: "r1", State: alert.StateFiring,
		Severity: alert.SeverityCritical, Metric: "probectl_probe_loss_ratio",
		Labels: map[string]string{"server_address": "192.0.2.10"}, Value: 0.9, At: time.Unix(100, 0),
	}
	s := signalFromAlert(a)
	if s.TenantID != "t1" || s.Plane != "network" || s.Kind != "alert.firing" {
		t.Errorf("signal = %+v", s)
	}
	if s.Severity != incident.SeverityCritical || s.Target != "192.0.2.10" {
		t.Errorf("severity/target = %q/%q", s.Severity, s.Target)
	}
	if s.Attributes["metric"] != "probectl_probe_loss_ratio" || s.Attributes["rule_id"] != "r1" {
		t.Errorf("attributes = %+v", s.Attributes)
	}
}

func TestSignalFromBGPEvent(t *testing.T) {
	e := &bgpv1.BGPEvent{
		TenantId: "t1", EventType: bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
		Severity: bgpv1.Severity_SEVERITY_CRITICAL, Prefix: "192.0.2.0/24",
		Message: "possible hijack", DetectedAtUnixNano: 100 * 1_000_000_000,
		Collector: "rrc00", NewOriginAsn: 64500, OldOriginAsn: 64496, Confidence: 0.85,
		ExpectedOrigins: []uint32{64496, 64497}, NewAsPath: []uint32{64511, 64500},
		PeerAsn: 64511, PeerAddress: "192.0.2.1",
	}
	s := signalFromBGPEvent(e)
	// DPR-057: the detection context reaches the tenant's event read model.
	for k, want := range map[string]string{
		"confidence": "0.85", "old_origin_asn": "64496", "expected_origins": "64496,64497",
		"new_as_path": "64511,64500", "peer_asn": "64511", "peer_address": "192.0.2.1",
	} {
		if got := s.Attributes[k]; got != want {
			t.Errorf("attribute %s = %q, want %q", k, got, want)
		}
	}
	if minimal := signalFromBGPEvent(&bgpv1.BGPEvent{TenantId: "t1", Prefix: "p"}); minimal.Attributes["old_origin_asn"] != "" || minimal.Attributes["expected_origins"] != "" {
		t.Errorf("absent context must not render empty attributes: %+v", minimal.Attributes)
	}
	if s.TenantID != "t1" || s.Plane != "bgp" || s.Kind != "bgp.possible_hijack" {
		t.Errorf("signal = %+v", s)
	}
	if s.Severity != incident.SeverityCritical || s.Target != "192.0.2.0/24" || s.Prefix != "192.0.2.0/24" {
		t.Errorf("severity/target/prefix = %q/%q/%q", s.Severity, s.Target, s.Prefix)
	}
	if s.Attributes["collector"] != "rrc00" || s.Attributes["new_origin_asn"] != "64500" {
		t.Errorf("attributes = %+v", s.Attributes)
	}
	if !s.OccurredAt.Equal(time.Unix(100, 0)) {
		t.Errorf("occurred_at = %v", s.OccurredAt)
	}
}

func TestBGPKindAndSeverity(t *testing.T) {
	kinds := map[bgpv1.EventType]string{
		bgpv1.EventType_EVENT_TYPE_ORIGIN_CHANGE:   "origin_change",
		bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK: "possible_hijack",
		bgpv1.EventType_EVENT_TYPE_POSSIBLE_LEAK:   "possible_leak",
		bgpv1.EventType_EVENT_TYPE_RPKI_INVALID:    "rpki_invalid",
	}
	for et, want := range kinds {
		if got := bgpKind(et); got != want {
			t.Errorf("bgpKind(%v) = %q, want %q", et, got, want)
		}
	}
	if bgpSeverity(bgpv1.Severity_SEVERITY_CRITICAL) != incident.SeverityCritical {
		t.Error("critical severity")
	}
	if bgpSeverity(bgpv1.Severity_SEVERITY_UNSPECIFIED) != incident.SeverityInfo {
		t.Error("unspecified should map to info")
	}
}

// Returning the correlation error is the BGP durability contract: Kafka keeps
// the source offset uncommitted and redelivers the event instead of sending it
// to a dead-letter topic.
func TestBGPIncidentConsumerReturnsCorrelatorError(t *testing.T) {
	wantErr := errors.New("incident store down")
	c := incident.NewCorrelator(failingIncidentStore{err: wantErr}, time.Minute, intelTestLog())
	consumer := NewBGPIncidentConsumer(bus.NewMemory(), c, intelTestLog())
	raw, err := proto.Marshal(&bgpv1.BGPEvent{
		TenantId:  "tenant-a",
		EventType: bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
		Severity:  bgpv1.Severity_SEVERITY_CRITICAL,
		Prefix:    "203.0.113.0/24",
		Message:   "possible hijack",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = consumer.handleLane(context.Background(), bus.Message{
		Topic: bus.BGPEventsTopic,
		Key:   []byte("tenant-a"),
		Value: raw,
	}, "")
	if !errors.Is(err, wantErr) {
		t.Fatalf("handleLane error = %v, want wrapping %v", err, wantErr)
	}
}

func TestBGPIncidentConsumerRejectsEnvelopePayloadTenantMismatch(t *testing.T) {
	store := &recordingIncidentStore{}
	c := incident.NewCorrelator(store, time.Minute, intelTestLog())
	consumer := NewBGPIncidentConsumer(bus.NewMemory(), c, intelTestLog())
	raw, err := proto.Marshal(&bgpv1.BGPEvent{
		TenantId:  "tenant-a",
		EventType: bgpv1.EventType_EVENT_TYPE_POSSIBLE_HIJACK,
		Severity:  bgpv1.Severity_SEVERITY_CRITICAL,
		Prefix:    "203.0.113.0/24",
		Message:   "possible hijack",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = consumer.handleLane(context.Background(), bus.Message{
		Topic: bus.BGPEventsTopic,
		Key:   []byte("tenant-b"),
		Value: raw,
	}, "")
	if err != nil {
		t.Fatalf("mismatched event should be dropped without retry: %v", err)
	}
	if store.openCalls != 0 || store.created != 0 || store.appended != 0 {
		t.Fatalf("mismatched event reached incident store: open=%d created=%d appended=%d", store.openCalls, store.created, store.appended)
	}
}

type failingIncidentStore struct {
	err error
}

func (s failingIncidentStore) OpenIncidents(context.Context, string) ([]*incident.Incident, error) {
	return nil, s.err
}

func (s failingIncidentStore) Create(context.Context, *incident.Incident) (*incident.Incident, error) {
	return nil, errors.New("unexpected create")
}

func (s failingIncidentStore) AppendSignal(context.Context, string, string, incident.Signal) (*incident.Incident, error) {
	return nil, errors.New("unexpected append")
}

func (s failingIncidentStore) ActiveCorrelationOverrides(context.Context, string, incident.Signal) ([]incident.CorrelationOverride, error) {
	return nil, s.err
}

type recordingIncidentStore struct {
	openCalls int
	created   int
	appended  int
}

func (s *recordingIncidentStore) OpenIncidents(context.Context, string) ([]*incident.Incident, error) {
	s.openCalls++
	return nil, nil
}

func (s *recordingIncidentStore) Create(_ context.Context, inc *incident.Incident) (*incident.Incident, error) {
	s.created++
	return inc, nil
}

func (s *recordingIncidentStore) AppendSignal(context.Context, string, string, incident.Signal) (*incident.Incident, error) {
	s.appended++
	return nil, errors.New("unexpected append")
}

func (s *recordingIncidentStore) ActiveCorrelationOverrides(context.Context, string, incident.Signal) ([]incident.CorrelationOverride, error) {
	return nil, nil
}
