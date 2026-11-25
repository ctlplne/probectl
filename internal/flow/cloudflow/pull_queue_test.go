// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

const (
	queueFixtureBucket     = "customer-flow-exports"
	queueFixtureKey        = "vpc/logs/export.jsonl"
	queueFixtureGeneration = "1700000012345"
)

func privateQueueStateDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "queue-state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func queueFixtureConfig(state string) flow.CloudImportConfig {
	return flow.CloudImportConfig{Provider: flow.ProtoGCPVPCFlowLogs, Queue: &flow.CloudQueueConfig{
		Project: "project-flow-demo", Subscription: "flow-import", CredentialRef: "env:QUEUE_READ",
		Object: flow.CloudObjectConfig{Bucket: queueFixtureBucket, CredentialRef: "env:OBJECT_READ"},
		Prefix: "vpc/logs/", StateDir: state,
	}}
}

func queueFixtureEvent(at time.Time, bucket, key, generation string) map[string]string {
	return map[string]string{"eventType": "OBJECT_FINALIZE", "eventTime": at.UTC().Format(time.RFC3339Nano),
		"bucketId": bucket, "objectId": key, "objectGeneration": generation}
}

func queueFixtureResponse(t *testing.T, events ...map[string]string) []byte {
	t.Helper()
	messages := make([]map[string]any, 0, len(events))
	for _, attrs := range events {
		messages = append(messages, map[string]any{"ackId": "internal-fixture-ack-handle", "message": map[string]any{"attributes": attrs}})
	}
	body, err := json.Marshal(map[string]any{"receivedMessages": messages})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestCloudQueueScopesNotificationsAndCheckpointsOnlyDurableBrokerDelivery(t *testing.T) {
	state := privateQueueStateDir(t)
	configFile := filepath.Join(t.TempDir(), "flow.yaml")
	yml := `apiVersion: probectl.io/flow-agent/v1
tenant_id: fixture-tenant
agent_id: queue-reader
bus:
  mode: nats
  brokers: [nats.example.test:4222]
netflow: {enabled: false}
ipfix: {enabled: false}
sflow: {enabled: false}
cloud_import:
  provider: gcp_vpc_flow_logs
  queue:
    project: project-flow-demo
    subscription: flow-import
    credential_ref: env:QUEUE_READ
    object:
      bucket: customer-flow-exports
      credential_ref: env:OBJECT_READ
    prefix: vpc/logs/
    state_dir: ` + state + "\n"
	if err := os.WriteFile(configFile, []byte(yml), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := flow.Load(configFile)
	if err != nil || loaded.CloudImport.Queue == nil || loaded.CloudImport.Object != nil {
		t.Fatal("standard flow collector did not load the queue selection", err)
	}

	stamp := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	good := queueFixtureEvent(stamp, queueFixtureBucket, queueFixtureKey, queueFixtureGeneration)
	badClock := queueFixtureEvent(stamp.Add(24*time.Hour), queueFixtureBucket, queueFixtureKey, queueFixtureGeneration)
	envelope := queueFixtureResponse(t,
		queueFixtureEvent(stamp, "foreign-flow-bucket", queueFixtureKey, queueFixtureGeneration),
		queueFixtureEvent(stamp, queueFixtureBucket, "vpc/logs-foreign/object.jsonl", queueFixtureGeneration),
		queueFixtureEvent(stamp, queueFixtureBucket, "vpc/logs/../other/object.jsonl", queueFixtureGeneration),
		queueFixtureEvent(stamp, queueFixtureBucket, queueFixtureKey, ""),
		badClock, good)
	resolver := objectFixtureResolver(t, func(name string) string {
		return map[string]string{"QUEUE_READ": "fixture-queue-role", "OBJECT_READ": "fixture-object-role"}[name]
	})
	transfer := newCloudObjectTransfer()
	var polls, downloads int
	transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "pubsub.googleapis.com":
			polls++
			if req.Method != http.MethodPost || !strings.HasSuffix(req.URL.Path, "/subscriptions/flow-import:pull") ||
				req.Header.Get("Authorization") != "Bearer fixture-queue-role" {
				t.Fatal("queue reader attempted a method outside the configured subscription")
			}
			return objectFixtureResponse(req, envelope), nil
		case "storage.googleapis.com":
			downloads++
			if req.Method != http.MethodGet || req.URL.Path != "/download/storage/v1/b/"+queueFixtureBucket+"/o/"+queueFixtureKey ||
				req.URL.Query().Get("generation") != queueFixtureGeneration || req.Header.Get("Authorization") != "Bearer fixture-object-role" {
				t.Fatal("notification changed bucket, object, revision or credential scope")
			}
			// Omit provider clocks so the stable notification clock is visible.
			return objectFixtureResponse(req, []byte(`{"jsonPayload":{"connection":{"src_ip":"10.0.0.5","dest_ip":"192.0.2.20","protocol":6},"bytes_sent":100,"packets_sent":5}}`)), nil
		default:
			t.Fatal("unexpected outbound queue request", req.URL.Host)
			return nil, nil
		}
	})
	em := &captureEmitter{}
	lease, err := openQueueCheckpoint(t.Context(), *loaded.CloudImport.Queue, loaded.TenantID, loaded.CloudImport.Provider, stamp)
	if err != nil {
		t.Fatal(err)
	}
	_, overlapErr := transfer.pullQueue(t.Context(), loaded.CloudImport, loaded.TenantID, loaded.AgentID, resolver, em,
		func(context.Context) error { return nil })
	if err := lease.close(); err != nil {
		t.Fatal(err)
	}
	if overlapErr == nil || polls != 0 {
		t.Fatal("parallel collector acquired another lease for the same state", overlapErr)
	}

	notDurable := errors.New("fixture broker acknowledgement failed")
	result, err := transfer.pullQueue(t.Context(), loaded.CloudImport, loaded.TenantID, loaded.AgentID, resolver, em,
		func(context.Context) error { return notDurable })
	if !errors.Is(err, notDurable) || result.Objects != 0 || result.OutOfScope != 5 || len(em.recs) != 1 {
		t.Fatalf("failed broker send was treated as durable: %+v, records %d, %v", result, len(em.recs), err)
	}

	flushes := 0
	flush := func(context.Context) error { flushes++; return nil }
	result, err = transfer.pullQueue(t.Context(), loaded.CloudImport, loaded.TenantID, loaded.AgentID, resolver, em, flush)
	if err != nil || result.Objects != 1 || result.Records != 1 || len(em.recs) != 2 || em.recs[0] != em.recs[1] ||
		!em.recs[1].ObservedAt.Equal(stamp) || em.recs[1].TenantID != "fixture-tenant" {
		t.Fatalf("retry lost its scope or changed the replayed row: %+v, records %d, %v", result, len(em.recs), err)
	}
	result, err = transfer.pullQueue(t.Context(), loaded.CloudImport, loaded.TenantID, loaded.AgentID, resolver, em, flush)
	if err != nil || result.Replayed != 1 || result.OutOfScope != 5 || polls != 3 || downloads != 2 || flushes != 1 || len(em.recs) != 2 {
		t.Fatalf("completed generation was republished: %+v, polls %d, gets %d, flushes %d, %v", result, polls, downloads, flushes, err)
	}
}
