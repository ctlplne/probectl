// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package cloudflow

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type queueFixtureWarehouse struct{ store flowstore.Store }

func (w queueFixtureWarehouse) Emit(ctx context.Context, records []flow.Record) error {
	rows := make([]flowstore.Row, 0, len(records))
	for _, r := range records {
		rows = append(rows, rowFromRecord(r))
	}
	return w.store.Insert(ctx, rows)
}

func TestCloudQueueKeepsOverlappingGenerationAndCheckpointsSeparateByTenant(t *testing.T) {
	endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if endpoint == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL is required for cloud queue isolation")
	}
	store, err := flowstore.NewClickHouse(endpoint, 0)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	commonState := privateQueueStateDir(t)
	cfg := queueFixtureConfig(commonState)
	red, blue := uuid.NewString(), uuid.NewString()
	for i, tenant := range []string{red, blue} {
		other := []string{blue, red}[i]
		objectToken := fmt.Sprintf("tenant-%d-object-role", i)
		queueToken := fmt.Sprintf("tenant-%d-queue-role", i)
		resolver := objectFixtureResolver(t, func(name string) string {
			return map[string]string{"QUEUE_READ": queueToken, "OBJECT_READ": objectToken}[name]
		})
		transfer := newCloudObjectTransfer()
		body := []byte(fmt.Sprintf(`{"tenant_id":%q,"jsonPayload":{"connection":{`+
			`"src_ip":"10.0.0.5","dest_ip":"192.0.2.20","src_port":5000,"dest_port":443,"protocol":6},`+
			`"bytes_sent":%d,"packets_sent":5}}`+"\n", other, 100*(i+1)))
		valid := queueFixtureEvent(stamp, queueFixtureBucket, queueFixtureKey, queueFixtureGeneration)
		valid["tenantId"] = other
		foreign := queueFixtureEvent(stamp, "foreign-flow-exports", queueFixtureKey, queueFixtureGeneration)
		envelope := queueFixtureResponse(t, foreign, valid)
		gets := 0
		transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
			switch {
			case req.URL.Host == "pubsub.googleapis.com" && req.Header.Get("Authorization") == "Bearer "+queueToken:
				return objectFixtureResponse(req, envelope), nil
			case req.URL.Host == "storage.googleapis.com" && req.Header.Get("Authorization") == "Bearer "+objectToken &&
				req.URL.Path == "/download/storage/v1/b/"+queueFixtureBucket+"/o/"+queueFixtureKey:
				gets++
				return objectFixtureResponse(req, body), nil
			default:
				return nil, fmt.Errorf("request changed the tenant's queue or object scope")
			}
		})
		warehouse := queueFixtureWarehouse{store}
		flush := func(context.Context) error { return nil } // The fixture inserts synchronously.
		p, err := transfer.pullQueue(t.Context(), cfg, tenant, "shared-collector", resolver, warehouse, flush)
		if err != nil || p.Objects != 1 || p.Records != 1 || p.OutOfScope != 1 || gets != 1 {
			t.Fatalf("first import for tenant %d lost or leaked its generation: %+v, gets %d, %v", i, p, gets, err)
		}
		t.Cleanup(func() {
			erase, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := store.DeleteTenant(erase, tenant); err != nil {
				t.Error(err)
			}
		})
		p, err = transfer.pullQueue(t.Context(), cfg, tenant, "shared-collector", resolver, warehouse, flush)
		if err != nil || p.Replayed != 1 || gets != 1 {
			t.Fatalf("second import for tenant %d lost its own replay state: %+v, gets %d, %v", i, p, gets, err)
		}
	}
	for i, tenant := range []string{red, blue} {
		rows, err := store.TopTalkers(t.Context(), flowstore.TopQuery{
			TenantID: tenant, By: flowstore.BySrc, Window: time.Hour, Now: stamp.Add(time.Minute), Limit: 5,
		})
		if err != nil || len(rows) != 1 || rows[0].Key != "10.0.0.5" || rows[0].Bytes != uint64(100*(i+1)) {
			t.Fatalf("tenant %d did not get exactly its own projected flow: %+v, %v", i, rows, err)
		}
	}
}
