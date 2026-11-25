// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
)

const (
	queueFixtureETag      = `"2e235e01a93da1f4a2b7f16cbc9f9190"`
	queueFixtureOwner     = "111122223333"
	queueFixtureAccount   = "objectflows"
	nativeQueueFixtureKey = "vpc/logs/a +.json"
)

func TestCloudQueueBudgetsIncludeSkippedNotices(t *testing.T) {
	for _, tc := range []struct {
		name string
		add  func(*queueNotices, string) error
		wrap func(string) string
	}{
		{"S3", (*queueNotices).addS3Records, func(array string) string { return `{"Records":` + array + `}` }},
		{"Azure Blob", func(n *queueNotices, body string) error { return n.addAzureRecords(queueFixtureAccount, body) },
			func(array string) string { return array }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var notices queueNotices
			makeArray := func(count int) string { return "[" + strings.Repeat("{},", count-1) + "{}]" }
			if err := tc.add(&notices, tc.wrap(makeArray(queueMaxNotices+1))); !errors.Is(err, errQueueBatchLimit) ||
				len(notices.objects) != 0 || notices.skipped != 0 {
				t.Fatalf("oversized notification array left a partial batch: %+v, %v", notices, err)
			}
			if err := tc.add(&notices, tc.wrap(makeArray(queueMaxNotices))); err != nil || notices.skipped != queueMaxNotices {
				t.Fatalf("notification array at the budget was not counted: %+v, %v", notices, err)
			}
			if err := tc.add(&notices, "{}"); !errors.Is(err, errQueueBatchLimit) || notices.skipped != queueMaxNotices {
				t.Fatalf("an ignored message exceeded the cumulative notice budget: %+v, %v", notices, err)
			}
		})
	}
	t.Run("Azure outer message budget", func(t *testing.T) {
		const message = "<QueueMessage><MessageText>{}</MessageText></QueueMessage>"
		batch := func(count int) []byte {
			return []byte("<QueueMessagesList>" + strings.Repeat(message, count) + "</QueueMessagesList>")
		}
		within, err := decodeAzureQueueMessages(batch(queueMaxMessages), queueFixtureAccount)
		if err != nil || within.skipped != queueMaxMessages {
			t.Fatalf("Azure message batch at the limit was not accepted: %+v, %v", within, err)
		}
		beyond, err := decodeAzureQueueMessages(batch(queueMaxMessages+1), queueFixtureAccount)
		if !errors.Is(err, errQueueBatchLimit) || beyond.skipped != 0 {
			t.Fatalf("Azure message batch over the limit left partial results: %+v, %v", beyond, err)
		}
	})
	t.Run("Azure complete response", func(t *testing.T) {
		body := nativeAzureResponse(time.Now().UTC(), queueFixtureBucket, queueFixtureETag)
		valid, err := decodeAzureQueueMessages(append(bytes.Clone(body), "\n<!-- end -->\n"...), queueFixtureAccount)
		if err != nil || len(valid.objects) != 2 || valid.skipped != 1 {
			t.Fatalf("complete Azure response lost notices: %+v, %v", valid, err)
		}
		for _, tail := range []string{"garbage", "<QueueMessagesList/>", "<!-- truncated"} {
			invalid, err := decodeAzureQueueMessages(append(bytes.Clone(body), tail...), queueFixtureAccount)
			if err == nil || len(invalid.objects) != 0 || invalid.skipped != 0 {
				t.Fatalf("Azure response with trailing %q left partial results: %+v, %v", tail, invalid, err)
			}
		}
		if invalid, err := decodeAzureQueueMessages(append([]byte("garbage"), body...), queueFixtureAccount); err == nil || len(invalid.objects) != 0 {
			t.Fatalf("Azure response with a leading text node left partial results: %+v, %v", invalid, err)
		}
	})
}

func nativeQueueFixture(provider Provider, state string) flow.CloudImportConfig {
	q := &flow.CloudQueueConfig{Prefix: "vpc/logs/", StateDir: state,
		Object:        flow.CloudObjectConfig{Bucket: queueFixtureBucket, CredentialRef: "env:OBJECT_READ"},
		CredentialRef: "env:QUEUE_READ", Name: "flow-events"}
	if provider == ProviderAWSVPC {
		q.Account, q.Region = queueFixtureOwner, "eu-west-1"
		q.Object.ExpectedOwner, q.Object.Region = queueFixtureOwner, "eu-west-1"
	} else {
		q.Account, q.Object.Account = "notificationflows", queueFixtureAccount
	}
	return flow.CloudImportConfig{Provider: string(provider), Queue: q}
}

func nativeSQSResponse(stamp time.Time, bucket, encodedKey, etag, version string) []byte {
	event := fmt.Sprintf(`{"Records":[{"eventVersion":"2.1","eventSource":"aws:s3","eventName":"ObjectCreated:Put",
		"eventTime":%q,"s3":{"bucket":{"name":%q},"object":{"key":%q,"eTag":%q,"versionId":%q}}}]}`,
		stamp.Format(time.RFC3339Nano), bucket, encodedKey, etag, version)
	foreign := strings.Replace(event, bucket, "foreign-notification-bucket", 1)
	return []byte(fmt.Sprintf(`{"Messages":[{"Body":%q},{"Body":%q}]}`, foreign, event))
}

func nativeAzureResponse(stamp time.Time, bucket, etag string) []byte {
	format := `{"eventType":"Microsoft.Storage.BlobCreated","eventTime":%q,"data":{"url":%q,"eTag":%q}}`
	valid := fmt.Sprintf(format, stamp.Format(time.RFC3339Nano), "https://"+queueFixtureAccount+".dfs.core.windows.net/"+bucket+"/vpc/logs/a%20%2B.json", etag)
	foreign := strings.Replace(valid, queueFixtureAccount+".dfs", "foreignaccount.dfs", 1)
	wildcard := fmt.Sprintf(format, stamp.Format(time.RFC3339Nano), "https://"+queueFixtureAccount+".blob.core.windows.net/"+bucket+"/vpc/logs/older.json", "*")
	return []byte("<QueueMessagesList><QueueMessage><MessageText>" + base64.StdEncoding.EncodeToString([]byte("["+foreign+","+wildcard+","+valid+"]")) +
		"</MessageText></QueueMessage></QueueMessagesList>")
}

func TestNativeCloudQueuesPinAWSAndAzureObjectReads(t *testing.T) {
	stamp := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	resolver := objectFixtureResolver(t, func(name string) string {
		return map[string]string{
			"SQS_READ":    `{"access_key_id":"FIXTUREQUEUE0001","secret_access_key":"fixture-signing-material","session_token":"queue-session"}`,
			"S3_READ":     `{"access_key_id":"FIXTUREOBJECT001","secret_access_key":"fixture-object-material","session_token":"object-session"}`,
			"QUEUE_READ":  "fixture-azure-queue-role",
			"OBJECT_READ": "fixture-azure-object-role",
		}[name]
	})
	t.Run("SQS unversioned S3 object", func(t *testing.T) {
		cfg := nativeQueueFixture(ProviderAWSVPC, privateQueueStateDir(t))
		cfg.Queue.CredentialRef, cfg.Queue.Object.CredentialRef = "env:SQS_READ", "env:S3_READ"
		envelope := nativeSQSResponse(stamp, queueFixtureBucket, "vpc%2Flogs%2Fa+%2B.json", strings.Trim(queueFixtureETag, `"`), "null")
		body := readFixture(t, "aws-vpc-flow.log")
		transfer := newCloudObjectTransfer()
		polls, gets := 0, 0
		transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
			polls++
			var receive struct {
				QueueURL          string `json:"QueueUrl"`
				VisibilityTimeout *int   `json:"VisibilityTimeout"`
			}
			if err := json.NewDecoder(req.Body).Decode(&receive); err != nil || req.Method != http.MethodPost || req.URL.Path != "/" ||
				req.URL.Host != "sqs.eu-west-1.amazonaws.com" || receive.QueueURL != "https://sqs.eu-west-1.amazonaws.com/111122223333/flow-events" ||
				receive.VisibilityTimeout == nil || *receive.VisibilityTimeout != 0 || req.Header.Get("X-Amz-Target") != "AmazonSQS.ReceiveMessage" ||
				req.Header.Get("X-Amz-Security-Token") != "queue-session" ||
				!strings.Contains(req.Header.Get("Authorization"), "/eu-west-1/sqs/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target,") {
				t.Fatal("SQS request changed the signed receive-only scope", err)
			}
			return objectFixtureResponse(req, envelope), nil
		})
		transfer.copyS3 = func(_ context.Context, cfg objectstore.S3Config, object objectstore.S3ReadRevision, dst io.Writer, _ int64) (int64, error) {
			gets++
			if cfg.Bucket != queueFixtureBucket || cfg.SessionToken != "object-session" || object.Key != nativeQueueFixtureKey ||
				object.Version != "" || object.ETag != queueFixtureETag || object.ExpectedOwner != queueFixtureOwner {
				t.Fatal("S3 read did not require the scoped unversioned revision", object)
			}
			return io.Copy(dst, bytes.NewReader(body))
		}
		em := &captureEmitter{}
		for i := range 2 {
			p, err := transfer.pullQueue(t.Context(), cfg, "tenant-red", "collector", resolver, em, func(context.Context) error { return nil })
			if err != nil || p.Objects != 1-i || p.Replayed != i || p.OutOfScope != 1 || gets != 1 || polls != i+1 {
				t.Fatalf("AWS failed scope or retry checks: %+v, %d/%d, %v", p, gets, polls, err)
			}
		}
	})
	t.Run("Azure queue and Blob ETag", func(t *testing.T) {
		cfg := nativeQueueFixture(ProviderAzureNSG, privateQueueStateDir(t))
		envelope := nativeAzureResponse(stamp, queueFixtureBucket, queueFixtureETag)
		body := readFixture(t, "azure-nsg-flow.jsonl")
		transfer := newCloudObjectTransfer()
		gets := 0
		transfer.client.Transport = fixtureObjectTransport(func(req *http.Request) (*http.Response, error) {
			switch req.URL.Host {
			case "notificationflows.queue.core.windows.net":
				if req.Method != http.MethodGet || req.URL.Path != "/flow-events/messages" || req.URL.Query().Get("peekonly") != "true" ||
					req.Header.Get("Authorization") != "Bearer fixture-azure-queue-role" {
					t.Fatal("Azure queue request did not stay in peek scope")
				}
				return objectFixtureResponse(req, envelope), nil
			case "objectflows.blob.core.windows.net":
				gets++
				if req.Method != http.MethodGet || req.URL.Path != "/"+queueFixtureBucket+"/"+nativeQueueFixtureKey ||
					req.Header.Get("If-Match") != queueFixtureETag || req.Header.Get("Authorization") != "Bearer fixture-azure-object-role" {
					t.Fatal("Azure object read lost its configured account or ETag")
				}
				res := objectFixtureResponse(req, body)
				res.Header.Set("ETag", queueFixtureETag)
				if gets == 1 {
					res.Header.Set("ETag", `"different-generation"`)
				}
				return res, nil
			default:
				return nil, fmt.Errorf("untrusted notification selected an outbound host")
			}
		})
		em := &captureEmitter{}
		flush := func(context.Context) error { return nil }
		p, err := transfer.pullQueue(t.Context(), cfg, "tenant-blue", "collector", resolver, em, flush)
		if err == nil || p.Objects != 0 || p.OutOfScope != 2 || len(em.recs) != 0 || gets != 1 {
			t.Fatalf("Azure accepted a different object generation: %+v, gets %d, %v", p, gets, err)
		}
		p, err = transfer.pullQueue(t.Context(), cfg, "tenant-blue", "collector", resolver, em, flush)
		if err != nil || p.Objects != 1 || p.OutOfScope != 2 || len(em.recs) != 1 || gets != 2 {
			t.Fatalf("Azure did not retry the expected object: %+v, gets %d, %v", p, gets, err)
		}
	})
}
