// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

func TestAWSV4SignsTheExactSQSRequest(t *testing.T) {
	body := []byte(`{"QueueUrl":"https://sqs.eu-west-1.amazonaws.com/111122223333/demo","MaxNumberOfMessages":1}`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://sqs.eu-west-1.amazonaws.com/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonSQS.ReceiveMessage")
	SignAWSV4(req, body, AWSV4Credentials{AccessKey: "fixture-v4", SecretKey: []byte("a-synthetic-key"), SessionToken: "fixture-session"},
		"eu-west-1", "sqs", time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC), "content-type", "x-amz-target")
	want := "AWS4-HMAC-SHA256 Credential=fixture-v4/20260630/eu-west-1/sqs/aws4_request, " +
		"SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, " +
		"Signature=d8f89fe2779e88081351b7efd728c0c90128da360712041d0cac6a141956d037"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatal("signed request differs from the independent SigV4 fixture")
	}
}
