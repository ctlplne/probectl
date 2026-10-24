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
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
)

// topicEnsurerFake is a broker-backed bus whose metadata read and topic
// creation fail as configured.
type topicEnsurerFake struct {
	bus.Bus
	missing    []string
	missingErr error
	createErr  error
	createdFor []string
}

func (f *topicEnsurerFake) TopicsMissing(context.Context, []string) ([]string, error) {
	return f.missing, f.missingErr
}

// EnsureTopics reads metadata first, as bus.Kafka's does, so a broker that
// cannot be reached fails here too.
func (f *topicEnsurerFake) EnsureTopics(_ context.Context, topics []string, _ int32, _ int16) ([]string, error) {
	if f.missingErr != nil {
		return nil, f.missingErr
	}
	f.createdFor = topics
	if f.createErr != nil {
		return nil, f.createErr
	}
	return topics, nil
}

// TestEnsureBusTopicsDoesNotBlameTopicPermissionsForAnUnreachableBroker
// (DPR-335): the release image, pointed at a CA that did not sign the broker,
// refused to start with "unable to dial: tls: failed to verify certificate:
// x509: certificate signed by unknown authority — grant the bus user CREATE on
// probectl.*". The advice sent the operator to Kafka ACLs for a trust-store
// fault. A metadata failure now names the reachability, TLS and SASL
// settings; only a refused create keeps the CREATE advice.
func TestEnsureBusTopicsDoesNotBlameTopicPermissionsForAnUnreachableBroker(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx := context.Background()
	topics := []string{bus.NetworkResultsTopic}
	dialErr := errors.New("kafka metadata: unable to dial: tls: failed to verify certificate: x509: certificate signed by unknown authority")

	for _, create := range []bool{true, false} {
		cfg := &config.Config{BusCreateTopics: create, BusTopicPartitions: 1, BusTopicReplication: -1}
		err := ensureBusTopics(ctx, &topicEnsurerFake{Bus: bus.NewMemory(), missingErr: dialErr}, cfg, log, topics)
		if err == nil || !errors.Is(err, dialErr) {
			t.Fatalf("create=%t: a broker that cannot be verified must refuse startup with its cause, got %v", create, err)
		}
		if strings.Contains(err.Error(), "grant the bus user CREATE") {
			t.Errorf("create=%t: a TLS/dial failure must not be blamed on topic permissions: %v", create, err)
		}
		for _, want := range []string{"PROBECTL_BUS_BROKERS", "PROBECTL_BUS_TLS_CA_FILE", "PROBECTL_BUS_SASL_"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("create=%t: the metadata failure must point at %s: %v", create, want, err)
			}
		}
	}

	refused := errors.New("bus: kafka refused to create topic probectl.network.results: TOPIC_AUTHORIZATION_FAILED")
	fake := &topicEnsurerFake{Bus: bus.NewMemory(), missing: topics, createErr: refused}
	cfg := &config.Config{BusCreateTopics: true, BusTopicPartitions: 1, BusTopicReplication: -1}
	err := ensureBusTopics(ctx, fake, cfg, log, topics)
	if err == nil || !errors.Is(err, refused) || !strings.Contains(err.Error(), "grant the bus user CREATE") {
		t.Fatalf("a refused create must keep the CREATE advice, got %v", err)
	}
	if strings.Join(fake.createdFor, ",") != bus.NetworkResultsTopic {
		t.Fatalf("only the missing topics are created, got %v", fake.createdFor)
	}

	present := &topicEnsurerFake{Bus: bus.NewMemory()}
	if err := ensureBusTopics(ctx, present, cfg, log, topics); err != nil || present.createdFor != nil {
		t.Fatalf("nothing missing means nothing to create: err=%v created=%v", err, present.createdFor)
	}
}
