// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
)

func (source cloudObjectTransfer) sqsReceive(ctx context.Context, q flow.CloudQueueConfig, credential []byte) (queueNotices, error) {
	var result queueNotices
	auth, err := crypto.DecodeAWSV4Credentials(credential)
	if err != nil {
		return result, err
	}
	defer crypto.Zeroize(auth.SecretKey)
	origin := "https://" + crypto.AWSRegionalHost("sqs", q.Region)
	payload, _ := json.Marshal(struct {
		QueueURL            string `json:"QueueUrl"`
		MaxNumberOfMessages int    `json:"MaxNumberOfMessages"`
		VisibilityTimeout   int    `json:"VisibilityTimeout"`
		WaitTimeSeconds     int    `json:"WaitTimeSeconds"`
	}{origin + "/" + q.Account + "/" + q.Name, queueMaxMessages, 0, 5})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/", bytes.NewReader(payload))
	if err != nil {
		return result, errors.New("cloudflow: cannot construct the SQS receive request")
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonSQS.ReceiveMessage")
	crypto.SignAWSV4(req, payload, auth, q.Region, "sqs", time.Now(), "content-type", "x-amz-target")
	body, err := source.readQueueResponse(req, "SQS receive")
	if err != nil {
		return result, err
	}
	var response struct {
		Messages json.RawMessage `json:"Messages"`
	}
	if !decodeQueueJSONObject(body, &response) {
		return result, errors.New("cloudflow: invalid SQS receive response")
	}
	type sqsMessage struct {
		Body string `json:"Body"`
	}
	messages, err := decodeQueueArray[sqsMessage](response.Messages, queueMaxMessages)
	if err != nil {
		return result, fmt.Errorf("cloudflow: invalid SQS messages: %w", err)
	}
	for _, message := range messages {
		if err := result.addS3Records(message.Body); err != nil {
			return queueNotices{}, err
		}
	}
	return result, nil
}

type s3QueueEvent struct {
	EventVersion string `json:"eventVersion"`
	EventSource  string `json:"eventSource"`
	EventName    string `json:"eventName"`
	EventTime    string `json:"eventTime"`
	S3           struct {
		Bucket struct {
			Name string `json:"name"`
		} `json:"bucket"`
		Object struct {
			Key       string `json:"key"`
			VersionID string `json:"versionId"`
			ETag      string `json:"eTag"`
		} `json:"object"`
	} `json:"s3"`
}

func (n *queueNotices) addS3Records(body string) error {
	remaining := queueMaxNotices - len(n.objects) - n.skipped
	if remaining < 1 {
		return errQueueBatchLimit
	}
	var envelope struct {
		Records json.RawMessage `json:"Records"`
	}
	if !decodeQueueJSONObject([]byte(body), &envelope) {
		n.skipped++
		return nil
	}
	events, err := decodeQueueArray[s3QueueEvent](envelope.Records, remaining)
	if errors.Is(err, errQueueBatchLimit) {
		return err
	}
	if err != nil || len(events) == 0 {
		n.skipped++
		return nil
	}
	for _, event := range events {
		if event.EventSource != "aws:s3" || !strings.HasPrefix(event.EventVersion, "2.") || !strings.HasPrefix(event.EventName, "ObjectCreated:") {
			n.skipped++
			continue
		}
		key, err := url.QueryUnescape(event.S3.Object.Key)
		if err != nil {
			n.skipped++
			continue
		}
		version := event.S3.Object.VersionID
		if version == "null" {
			version = ""
		}
		n.objects = append(n.objects, objectNotice{bucket: event.S3.Bucket.Name, key: key, version: version,
			etag: strongNoticeETag(event.S3.Object.ETag), clock: event.EventTime})
	}
	return nil
}
