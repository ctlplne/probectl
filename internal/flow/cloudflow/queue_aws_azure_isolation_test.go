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
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestNativeCloudQueuesKeepAWSAndAzureReadsTenantScoped(t *testing.T) {
	endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if endpoint == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL is required for native cloud queue isolation")
	}
	store, err := flowstore.NewClickHouse(endpoint, 0)
	if err != nil {
		t.Fatal(err)
	}
	state := privateQueueStateDir(t)
	stamp := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	red, blue := uuid.NewString(), uuid.NewString()
	for i, tenant := range []string{red, blue} {
		t.Cleanup(func() {
			erase, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := store.DeleteTenant(erase, tenant); err != nil {
				t.Error(err)
			}
		})
		for _, provider := range []Provider{ProviderAWSVPC, ProviderAzureNSG, ProviderAzureVNet} {
			proveNativeQueueScope(t, store, state, stamp, i+1, tenant, provider)
		}
	}
	for i, tenant := range []string{red, blue} {
		rows, err := store.TopTalkers(t.Context(), flowstore.TopQuery{
			TenantID: tenant, By: flowstore.BySrc, Window: time.Hour, Now: stamp.Add(time.Minute), Limit: 5,
		})
		if err != nil || len(rows) != 1 || rows[0].Key != "10.0.0.5" || rows[0].Bytes != uint64(1300*(i+1)) {
			t.Fatalf("tenant %d read foreign traffic or lost part of its own: %+v, %v", i, rows, err)
		}
	}
}

func proveNativeQueueScope(t *testing.T, store flowstore.Store, state string, stamp time.Time, volume int, tenant string, provider Provider) {
	t.Helper()
	cfg := nativeQueueFixture(provider, state)
	queueToken := fmt.Sprintf("fixture-reader-%d", volume)
	objectToken := fmt.Sprintf("fixture-storage-%d", volume)
	resolver := objectFixtureResolver(t, func(name string) string {
		token := map[string]string{"QUEUE_READ": queueToken, "OBJECT_READ": objectToken}[name]
		if provider == ProviderAWSVPC {
			return fmt.Sprintf(`{"access_key_id":"FIXTUREACCESS0001","secret_access_key":"fixture-key","session_token":%q}`, token)
		}
		return token
	})
	awsBody := fmt.Sprintf("2 111122223333 eni-abc 10.0.0.5 192.0.2.20 5000 443 6 1 %d %d %d ACCEPT OK\n",
		100*volume, stamp.Unix()-5, stamp.Unix())
	azureBody := fmt.Sprintf(`{"records":[{"category":"FlowLogFlowEvent","flowLogVersion":4,
		"targetResourceID":"/subscriptions/demo/providers/Microsoft.Network/virtualNetworks/shared",
		"flowRecords":{"flows":[{"flowGroups":[{"flowTuples":["%d,10.0.0.5,192.0.2.20,5000,443,6,O,E,NX,4,%d,0,0"]}]}]}}]}`,
		stamp.Unix(), 1000*volume)
	isAzure := provider == ProviderAzureNSG || provider == ProviderAzureVNet
	if provider == ProviderAzureNSG {
		azureBody = fmt.Sprintf(`{
		  "records": [
		    {
		      "resourceId": "/subscriptions/demo/providers/Microsoft.Network/networkSecurityGroups/shared",
		      "properties": {"Version": 2, "flows": [
		        {"flows": [{"mac": "000D3A123456", "flowTuples": ["%d,10.0.0.5,192.0.2.20,5000,443,T,O,A,E,4,%d,0,0"]}]}
		      ]}
		    }
		  ]
		}`, stamp.Unix(), 200*volume)
	}
	transfer := newCloudObjectTransfer()
	gets := 0
	badAzureEnvelope := provider == ProviderAzureVNet && volume == 1
	transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
		switch {
		case provider == ProviderAWSVPC && req.URL.Host == "sqs.eu-west-1.amazonaws.com" && req.Header.Get("X-Amz-Security-Token") == queueToken:
			return objectFixtureResponse(req, nativeSQSResponse(stamp, queueFixtureBucket, "vpc/logs/a+%2B.json", queueFixtureETag, "configured-revision")), nil
		case isAzure && req.URL.Host == "notificationflows.queue.core.windows.net" && req.Header.Get("Authorization") == "Bearer "+queueToken:
			body := nativeAzureResponse(stamp, queueFixtureBucket, queueFixtureETag)
			if badAzureEnvelope {
				body = append(body, "<QueueMessagesList/>"...)
			}
			return objectFixtureResponse(req, body), nil
		case isAzure && req.URL.Host == "objectflows.blob.core.windows.net" && req.Header.Get("Authorization") == "Bearer "+objectToken:
			gets++
			res := objectFixtureResponse(req, []byte(azureBody))
			res.Header.Set("ETag", queueFixtureETag)
			return res, nil
		default:
			return nil, fmt.Errorf("notification altered the tenant's origin or credential")
		}
	})
	transfer.copyS3 = func(_ context.Context, cfg objectstore.S3Config, object objectstore.S3ReadRevision, dst io.Writer, _ int64) (int64, error) {
		gets++
		if provider != ProviderAWSVPC || cfg.SessionToken != objectToken || cfg.Bucket != queueFixtureBucket || object.Key != nativeQueueFixtureKey ||
			object.ExpectedOwner != queueFixtureOwner || object.Version != "configured-revision" || object.ETag != queueFixtureETag {
			return 0, fmt.Errorf("notification changed the tenant's S3 revision or credential")
		}
		return io.Copy(dst, strings.NewReader(awsBody))
	}
	if badAzureEnvelope {
		flushes := 0
		result, err := transfer.pullQueue(t.Context(), cfg, tenant, "shared-collector", resolver, queueFixtureWarehouse{store},
			func(context.Context) error {
				flushes++
				return nil
			})
		if err == nil || gets != 0 || flushes != 0 || result != (QueueImportResult{}) {
			t.Fatalf("invalid Azure queue response reached an object or broker: %+v, gets %d, flushes %d, %v", result, gets, flushes, err)
		}
		badAzureEnvelope = false
	}
	for invocation := range 2 {
		p, err := transfer.pullQueue(t.Context(), cfg, tenant, "shared-collector", resolver, queueFixtureWarehouse{store},
			func(context.Context) error { return nil })
		if err != nil || p.Objects != 1-invocation || p.Replayed != invocation || gets != 1 {
			t.Fatalf("%s failed its tenant checkpoint on poll %d: %+v, gets %d, %v", provider, invocation, p, gets, err)
		}
	}
}
