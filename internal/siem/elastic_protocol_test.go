// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package siem

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type elasticProtocolDoer func(*http.Request) (*http.Response, error)

func (f elasticProtocolDoer) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestElasticDocumentBatchProtocol(t *testing.T) {
	for _, tenant := range []string{"tenant-red", "tenant-blue"} {
		t.Run(tenant, func(t *testing.T) {
			events := batchEvents(tenant, 2)
			sender := NewHTTPSender(PresetElastic, "https://search.example/events/_doc?refresh=true", "qa:credential", AuthSchemeBasic, "application/json", elasticProtocolDoer(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/events/_bulk" || r.URL.RawQuery != "refresh=true" {
					t.Errorf("batch destination = %s", r.URL)
				}
				if r.Header.Get("Content-Type") != "application/x-ndjson" {
					t.Errorf("bulk content type = %s", r.Header.Get("Content-Type"))
				}
				body, _ := io.ReadAll(r.Body)
				want := ""
				for _, e := range events {
					want += "{\"index\":{}}\n" + string(ecsFormatter{}.Format(e)) + "\n"
				}
				if string(body) != want {
					t.Errorf("bulk action/document framing or tenant payload differs")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"errors":false,"items":[{"index":{"status":201}},{"index":{"status":201}}]}`))}, nil
			}))
			if err := sender.Send(context.Background(), ecsFormatter{}.FormatBatch(events)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestElasticBulkRejectsIncompleteOrFailedReceipt(t *testing.T) {
	for _, body := range []string{`{"errors":true,"items":[{"index":{"status":400}}]}`, `{"errors":false,"items":[]}`, `{"errors":false,"items":[{"index":{"status":429}}]}`, `{}`, `not json`} {
		sender := NewHTTPSender(PresetElastic, "https://search.example/events/_bulk", "", AuthSchemeNone, "application/json", elasticProtocolDoer(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		}))
		if err := sender.Send(context.Background(), ecsFormatter{}.Format(sampleEvent())); err == nil {
			t.Errorf("accepted failed/incomplete receipt %s", body)
		}
	}
}
