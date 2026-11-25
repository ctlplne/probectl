// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package cloudflow

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestCloudObjectPullKeepsCredentialsAndOverlappingFlowRowsTenantScoped(t *testing.T) {
	endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if endpoint == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL is required for cloud object isolation")
	}
	store, err := flowstore.NewClickHouse(endpoint, 0)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	red, blue := uuid.NewString(), uuid.NewString()
	lanes := map[string]string{"flow-red": red, "flow-blue": blue}
	broker := bus.NewMemory()
	defer broker.Close()
	consumer := pipeline.NewFlowConsumer(broker, store, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithNamespaceTenants(lanes).WithStrictTenantLanes(true)
	ctx, stop := context.WithTimeout(t.Context(), 20*time.Second)
	done := make(chan error, 1)
	go func() { done <- consumer.Run(ctx) }()
	defer func() {
		stop()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for ns := range lanes {
		topic, err := bus.TopicFor(ns, bus.FlowEventsTopic)
		if err != nil || !broker.WaitForSubscribers(ctx, topic, 1) {
			t.Fatal("cloud flow consumer did not subscribe on time", err)
		}
	}
	for i, tenant := range []string{red, blue} {
		ns, other := []string{"flow-red", "flow-blue"}[i], []string{blue, red}[i]
		token := "scoped-fixture-" + ns
		resolver := objectFixtureResolver(t, func(name string) string {
			if name == "CLOUD_FLOW_TOKEN" {
				return token
			}
			return ""
		})
		transfer := newCloudObjectTransfer()
		incomplete := true
		transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
			if req.Method != http.MethodGet || req.URL.Host != "storage.googleapis.com" ||
				req.URL.EscapedPath() != "/download/storage/v1/b/"+ns+"/o/shared%2Fexport.jsonl" ||
				req.Header.Get("Authorization") != "Bearer "+token {
				return nil, fmt.Errorf("tenant's scope or credentials changed")
			}
			body := []byte(fmt.Sprintf(`{"timestamp":%q,"tenant_id":%q,"jsonPayload":{`+
				`"connection":{"src_ip":"10.0.0.5","dest_ip":"192.0.2.20","src_port":5001,"dest_port":443,"protocol":6},`+
				`"bytes_sent":%d,"packets_sent":5}}`+"\n", stamp.Format(time.RFC3339), other, 120*(i+1)))
			if incomplete {
				body = append(bytes.Repeat(body, 1001), bytes.Repeat([]byte("x"), maxCloudLineBytes+1)...)
			}
			return objectFixtureResponse(req, body), nil
		})
		cfg := flow.CloudImportConfig{Provider: flow.ProtoGCPVPCFlowLogs, Object: &flow.CloudObjectConfig{
			Bucket: ns, Key: "shared/export.jsonl", CredentialRef: "env:CLOUD_FLOW_TOKEN",
		}}
		emit, err := flow.NewNamespacedBusEmitter(broker, tenant, ns)
		if err != nil {
			t.Fatal(err)
		}
		if n, _, err := transfer.pull(ctx, cfg, tenant, "same-cloud-agent", resolver, emit); err == nil || n != 0 {
			t.Fatalf("incomplete export published into the tenant's lane: %d %v", n, err)
		}
		incomplete = false
		n, bad, err := transfer.pull(ctx, cfg, tenant, "same-cloud-agent", resolver, emit)
		if n != 1 || bad != 0 || err != nil {
			t.Fatalf("tenant fixture did not emit only its cloud row: %d %d %v", n, bad, err)
		}
		t.Cleanup(func() {
			erase, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := store.DeleteTenant(erase, tenant); err != nil {
				t.Error(err)
			}
		})
	}
	if err := broker.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	for i, tenant := range []string{red, blue} {
		rows, err := store.TopTalkers(ctx, flowstore.TopQuery{TenantID: tenant, By: flowstore.BySrc,
			Window: time.Hour, Now: stamp.Add(time.Minute), Limit: 5})
		if err != nil || len(rows) != 1 || rows[0].Key != "10.0.0.5" || rows[0].Bytes != uint64(120*(i+1)) {
			t.Fatalf("tenant %d read foreign traffic or lost its own: %+v %v", i, rows, err)
		}
	}
}
