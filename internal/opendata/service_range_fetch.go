// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func serviceRangePublisherURL(publisher string) (string, error) {
	switch publisher {
	case "aws":
		return "https://ip-ranges.amazonaws.com/ip-ranges.json", nil
	case "google":
		return "https://www.gstatic.com/ipranges/goog.json", nil
	case "google_cloud":
		return "https://www.gstatic.com/ipranges/cloud.json", nil
	default:
		return "", errors.New("supported range publishers are aws, google and google_cloud")
	}
}

// FetchServiceRangeCache performs an explicitly requested BULK refresh. Requests
// contain no address, tenant, credential, telemetry or query selector. The nil
// client uses the existing hardened TLS door (docs/guardrails.md G7-2, 10, 12).
// All selected original documents validate before an atomic local replacement;
// failure leaves the prior cache and its original freshness untouched.
func FetchServiceRangeCache(ctx context.Context, path string, publishers []string, maxAge time.Duration, memoryBytes int64, client Doer) error {
	if len(publishers) == 0 || path == "" || maxAge <= 0 {
		return errors.New("an output cache, publishers and positive freshness are required")
	}
	if memoryBytes < 4096 {
		return ErrServiceRangeBudget
	}
	seen := map[string]bool{}
	for _, publisher := range publishers {
		if _, err := serviceRangePublisherURL(publisher); err != nil {
			return err
		}
		if seen[publisher] {
			return errors.New("range publishers must be unique")
		}
		seen[publisher] = true
	}
	if client == nil {
		client = defaultIntelClient()
	}
	envelope := serviceRangeEnvelope{Version: 1}
	remaining := memoryBytes / 32 // all response bodies plus full encoding/decode/index workspace
	for _, publisher := range publishers {
		input, err := fetchServiceRangeInput(ctx, client, publisher, remaining)
		if err != nil {
			return err
		}
		remaining -= int64(len(input.Data))
		envelope.Sources = append(envelope.Sources, input)
	}
	raw, err := encodeServiceRangeEnvelope(ctx, envelope)
	if err != nil {
		return errors.New("cannot encode complete original range documents")
	}
	if _, err := decodeServiceRanges(ctx, raw, maxAge, memoryBytes, time.Now()); err != nil {
		return err
	}
	return writeServiceRangeCache(ctx, path, raw)
}

func encodeServiceRangeEnvelope(ctx context.Context, envelope serviceRangeEnvelope) ([]byte, error) {
	var output bytes.Buffer
	output.WriteString(`{"version":1,"sources":[`)
	for i, input := range envelope.Sources {
		if err := validateServiceJSON(ctx, input.Data); err != nil {
			return nil, err
		}
		metadata, err := json.Marshal(struct {
			Publisher string    `json:"publisher"`
			FetchedAt time.Time `json:"fetched_at"`
			Complete  bool      `json:"complete"`
		}{input.Publisher, input.FetchedAt, input.Complete})
		if err != nil {
			return nil, err
		}
		if i > 0 {
			output.WriteByte(',')
		}
		output.Write(metadata[:len(metadata)-1])
		output.WriteString(`,"data":`)
		// Preserve the embedded original JSON instead of compacting/re-escaping
		// a RawMessage through json.Marshal; its digest survives offline transfer.
		output.Write(bytes.TrimSpace(input.Data))
		output.WriteByte('}')
	}
	output.WriteString(`]}`)
	return output.Bytes(), nil
}

func fetchServiceRangeInput(ctx context.Context, client Doer, publisher string, limit int64) (serviceRangeInput, error) {
	endpoint, err := serviceRangePublisherURL(publisher)
	if err != nil {
		return serviceRangeInput{}, err
	}
	if limit < 1 {
		return serviceRangeInput{}, ErrServiceRangeBudget
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return serviceRangeInput{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return serviceRangeInput{}, errors.New("published range bulk fetch failed; prior cache preserved")
	}
	if resp == nil || resp.Body == nil {
		return serviceRangeInput{}, errors.New("published range bulk fetch returned no complete body")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return serviceRangeInput{}, fmt.Errorf("published range bulk fetch returned status %d; prior cache preserved", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return serviceRangeInput{}, ErrServiceRangeBudget
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return serviceRangeInput{}, errors.New("incomplete published range body; prior cache preserved")
	}
	if int64(len(raw)) > limit {
		return serviceRangeInput{}, ErrServiceRangeBudget
	}
	fetched := time.Now().UTC()
	// A caching proxy's successful response must not renew the original fetch.
	// HTTP Age is seconds; reject malformed/overflowing ages rather than guess.
	if value := resp.Header.Get("Age"); value != "" {
		age, err := strconv.ParseInt(value, 10, 64)
		if err != nil || age < 0 || age > int64((time.Duration(1<<63-1))/time.Second) {
			return serviceRangeInput{}, errors.New("invalid published range cache age")
		}
		fetched = fetched.Add(-time.Duration(age) * time.Second)
	}
	return serviceRangeInput{Publisher: publisher, FetchedAt: fetched, Complete: true, Data: raw}, nil
}

func writeServiceRangeCache(ctx context.Context, path string, raw []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("published range cache output must be a regular local file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot inspect published range cache output")
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".probectl-service-ranges-*")
	if err != nil {
		return errors.New("cannot create local published range cache")
	}
	temporary := f.Name()
	defer func() { _ = f.Close(); _ = os.Remove(temporary) }()
	if _, err := f.Write(raw); err != nil {
		return errors.New("cannot write complete published range cache")
	}
	if err := f.Sync(); err != nil {
		return errors.New("cannot sync complete published range cache")
	}
	if err := f.Close(); err != nil {
		return errors.New("cannot close complete published range cache")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("cannot atomically replace published range cache")
	}
	directory, err := os.Open(dir)
	if err != nil {
		return errors.New("cannot open published range cache directory for sync")
	}
	defer func() { _ = directory.Close() }()
	if err := directory.Sync(); err != nil {
		return errors.New("cannot sync published range cache directory")
	}
	return nil
}
