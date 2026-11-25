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
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/secrets"
)

const (
	queueMaxMessages      = 10
	queueMaxNotices       = 64
	queueMaxEnvelopeBytes = 1 << 20
	queuePollTimeout      = 25 * time.Second
	queueWorkTimeout      = 3 * time.Minute
)

type QueueImportResult struct {
	Objects, Records, Malformed, Replayed, OutOfScope int
}

type objectNotice struct {
	bucket, key, version, etag, clock string
}

type queueNotices struct {
	objects []objectNotice
	skipped int
}

var errQueueBatchLimit = errors.New("cloudflow: notification batch exceeds the entry budget")

// PullQueue performs one bounded read of the customer's notification
// subscription. It intentionally leaves acknowledgement and retention to the
// subscription owner. A checkpoint is written after the local broker flush.
func PullQueue(ctx context.Context, cfg flow.CloudImportConfig, tenant, agent string, resolver *secrets.Resolver,
	emitter flow.Emitter, flush func(context.Context) error) (QueueImportResult, error) {
	transfer := newCloudObjectTransfer()
	defer transfer.client.CloseIdleConnections()
	return transfer.pullQueue(ctx, cfg, tenant, agent, resolver, emitter, flush)
}

func (source cloudObjectTransfer) pullQueue(ctx context.Context, cfg flow.CloudImportConfig, tenant, agent string,
	resolver *secrets.Resolver, emitter flow.Emitter, flush func(context.Context) error) (QueueImportResult, error) {
	var result QueueImportResult
	if tenant == "" {
		return result, ErrNoTenant
	}
	if cfg.Queue == nil || resolver == nil || emitter == nil || flush == nil {
		return result, errors.New("cloudflow: queue configuration, secrets resolver, emitter and broker flush are required")
	}
	if err := cfg.Validate(); err != nil {
		return result, err
	}
	q := *cfg.Queue
	now := time.Now()
	work, cancel := context.WithTimeout(ctx, queueWorkTimeout)
	defer cancel()
	checkpoint, err := openQueueCheckpoint(work, q, tenant, cfg.Provider, now)
	if err != nil {
		return result, err
	}
	defer checkpoint.close()
	notices, err := source.readNotices(work, Provider(cfg.Provider), q, resolver)
	if err != nil {
		return result, err
	}
	result.OutOfScope = notices.skipped
	var failures []error
	for _, event := range notices.objects {
		if err := work.Err(); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		object, observed, ok := objectFromNotice(q, cfg.Provider, event, now)
		if !ok {
			result.OutOfScope++
			continue
		}
		revision := "version:" + object.Version
		if object.Version == "" {
			revision = "etag:" + event.etag
		}
		mark := checkpointDigest(object.Key, revision) + ".done"
		seen, err := checkpoint.contains(mark)
		if err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		if seen {
			result.Replayed++
			continue
		}
		if checkpoint.count == queueCheckpointLimit {
			return result, errors.Join(append(failures, errors.New("cloudflow: queue checkpoint is full"))...)
		}
		one := flow.CloudImportConfig{Provider: cfg.Provider, Object: &object}
		n, malformed, err := source.pullRevision(work, one, tenant, agent, resolver, emitter, event.etag, func() time.Time { return observed })
		result.Malformed += malformed
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if err := flush(work); err != nil {
			return result, errors.Join(append(failures, fmt.Errorf("cloudflow: acknowledge flow publication: %w", err))...)
		}
		if err := checkpoint.remember(mark); err != nil {
			return result, errors.Join(append(failures, err)...)
		}
		result.Objects++
		result.Records += n
	}
	return result, errors.Join(failures...)
}

func (source cloudObjectTransfer) readNotices(ctx context.Context, provider Provider, q flow.CloudQueueConfig, resolver *secrets.Resolver) (queueNotices, error) {
	poll, cancel := context.WithTimeout(ctx, queuePollTimeout)
	defer cancel()
	credential, release, err := resolver.ResolveBytesUncached(poll, q.CredentialRef)
	if err != nil {
		return queueNotices{}, errors.New("cloudflow: queue credential could not be resolved")
	}
	defer release()
	if len(credential) == 0 || len(credential) > maxCloudCredential {
		return queueNotices{}, errors.New("cloudflow: invalid queue credential size")
	}
	switch provider {
	case ProviderGCPVPC:
		return source.googlePull(poll, q, string(credential))
	case ProviderAWSVPC:
		return source.sqsReceive(poll, q, credential)
	case ProviderAzureNSG, ProviderAzureVNet:
		return source.azureQueuePeek(poll, q, string(credential))
	default:
		return queueNotices{}, ErrUnknownProvider
	}
}

type googleQueueMessage struct {
	Message struct {
		Attributes struct {
			EventType  string `json:"eventType"`
			Bucket     string `json:"bucketId"`
			Key        string `json:"objectId"`
			Generation string `json:"objectGeneration"`
			EventTime  string `json:"eventTime"`
		} `json:"attributes"`
	} `json:"message"`
}

func (source cloudObjectTransfer) googlePull(ctx context.Context, q flow.CloudQueueConfig, credential string) (queueNotices, error) {
	var result queueNotices
	if !visibleASCIICredential(credential) {
		return result, errors.New("cloudflow: invalid Pub/Sub access token")
	}
	u := url.URL{Scheme: "https", Host: "pubsub.googleapis.com",
		Path: "/v1/projects/" + q.Project + "/subscriptions/" + q.Subscription + ":pull"}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(),
		strings.NewReader(fmt.Sprintf(`{"maxMessages":%d}`, queueMaxMessages)))
	if err != nil {
		return result, errors.New("cloudflow: cannot construct the Pub/Sub pull request")
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	body, err := source.readQueueResponse(req, "Pub/Sub pull")
	if err != nil {
		return result, err
	}
	var envelope struct {
		Received json.RawMessage `json:"receivedMessages"`
	}
	if !decodeQueueJSONObject(body, &envelope) {
		return result, errors.New("cloudflow: invalid Pub/Sub pull response")
	}
	messages, err := decodeQueueArray[googleQueueMessage](envelope.Received, queueMaxMessages)
	if err != nil {
		return result, fmt.Errorf("cloudflow: invalid Pub/Sub messages: %w", err)
	}
	for _, row := range messages {
		attrs := row.Message.Attributes
		if attrs.EventType != "OBJECT_FINALIZE" || attrs.Generation == "" {
			result.skipped++
			continue
		}
		result.objects = append(result.objects, objectNotice{bucket: attrs.Bucket, key: attrs.Key,
			version: attrs.Generation, clock: attrs.EventTime})
	}
	return result, nil
}

func (source cloudObjectTransfer) readQueueResponse(req *http.Request, operation string) ([]byte, error) {
	resp, err := source.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflow: %s failed", operation)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflow: %s returned HTTP %d", operation, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, queueMaxEnvelopeBytes+1))
	if err != nil || len(body) > queueMaxEnvelopeBytes || (resp.ContentLength >= 0 && resp.ContentLength != int64(len(body))) {
		return nil, fmt.Errorf("cloudflow: %s response could not be read within the envelope budget", operation)
	}
	return body, nil
}

func decodeQueueJSONObject(body []byte, dst any) bool {
	body = bytes.TrimSpace(body)
	return len(body) != 0 && body[0] == '{' && json.Unmarshal(body, dst) == nil
}

// Decode one element at a time so the count cap bounds allocations as well
// as the number of notices processed.
func decodeQueueArray[T any](raw []byte, limit int) ([]T, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if start, err := decoder.Token(); err != nil || start != json.Delim('[') {
		return nil, errors.New("expected a notification array")
	}
	var values []T
	for decoder.More() {
		if len(values) >= limit {
			return nil, errQueueBatchLimit
		}
		var value T
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid notification entry")
		}
		values = append(values, value)
	}
	if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
		return nil, errors.New("unterminated notification array")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("extra data after the notification array")
	}
	return values, nil
}

func strongNoticeETag(raw string) string {
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	if raw == "*" || len(raw) > 128 || !visibleASCIICredential(raw) || strings.ContainsAny(raw, "\"\\,") || strings.HasPrefix(raw, "W/") {
		return ""
	}
	return `"` + raw + `"`
}

func objectFromNotice(q flow.CloudQueueConfig, provider string, event objectNotice, now time.Time) (flow.CloudObjectConfig, time.Time, bool) {
	object := q.Object
	object.Key, object.Version = event.key, event.version
	if event.bucket != object.Bucket || (object.Version == "" && event.etag == "") ||
		!strings.HasPrefix(object.Key, q.Prefix) || len(object.Key) == len(q.Prefix) {
		return flow.CloudObjectConfig{}, time.Time{}, false
	}
	if err := (flow.CloudImportConfig{Provider: provider, Object: &object}).Validate(); err != nil {
		return flow.CloudObjectConfig{}, time.Time{}, false
	}
	observed, err := time.Parse(time.RFC3339Nano, event.clock)
	nanos := observed.UnixNano()
	if err != nil || nanos <= 0 || !time.Unix(0, nanos).Equal(observed) || observed.After(now.Add(5*time.Minute)) {
		return flow.CloudObjectConfig{}, time.Time{}, false
	}
	return object, observed.UTC(), true
}
