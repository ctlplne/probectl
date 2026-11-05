// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
)

// Observe only numeric receipt fields. Request, credentials, URL, SQL, response
// headers/body bytes and every underlying budget/receipt validator are unchanged.
type completeSourceReadTrace struct {
	base   http.RoundTripper
	mu     sync.Mutex
	active bool
	counts completeSourceReadCounts
}

type completeSourceReadCounts struct {
	requests, summaries, rows, bytes, body, transportErrors, invalid uint64
	status, exception                                                uint64
	overflow                                                         bool
}

func observeCompleteSourceReads(client *http.Client) (*http.Client, *completeSourceReadTrace) {
	clone := *client
	trace := &completeSourceReadTrace{base: client.Transport}
	if trace.base == nil {
		trace.base = http.DefaultTransport
	}
	clone.Transport = trace
	return &clone, trace
}

func (p *completeSourceReadTrace) begin() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.counts, p.active = completeSourceReadCounts{}, true
}

func (p *completeSourceReadTrace) finish(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	c := p.counts
	p.active = false
	p.mu.Unlock()
	t.Logf("complete source generation numeric read headers: requests=%d parsed_summaries=%d read_rows=%d read_bytes=%d body_bytes=%d transport_failures=%d last_status=%d last_exception_code=%d invalid_numeric_headers=%d overflow=%t", c.requests, c.summaries, c.rows, c.bytes, c.body, c.transportErrors, c.status, c.exception, c.invalid, c.overflow)
}

func traceSourceNumber(raw string) (uint64, bool) {
	if len(raw) == 0 || len(raw) > 20 {
		return 0, false
	}
	number, err := strconv.ParseUint(raw, 10, 64)
	return number, err == nil && strconv.FormatUint(number, 10) == raw
}

func (p *completeSourceReadTrace) add(target *uint64, value uint64) {
	if value > ^uint64(0)-*target {
		p.counts.overflow = true
		return
	}
	*target += value
}

func (p *completeSourceReadTrace) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := p.base.RoundTrip(request)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.active {
		return response, err
	}
	p.add(&p.counts.requests, 1)
	if err != nil {
		p.add(&p.counts.transportErrors, 1)
		return response, err
	}
	p.counts.status = uint64(response.StatusCode)
	if codes := response.Header.Values("X-ClickHouse-Exception-Code"); len(codes) == 1 {
		if value, ok := traceSourceNumber(codes[0]); ok && value <= 1<<32-1 {
			p.counts.exception = value
		} else {
			p.add(&p.counts.invalid, 1)
		}
	}
	values := response.Header.Values("X-ClickHouse-Summary")
	var receipt struct {
		Rows  string `json:"read_rows"`
		Bytes string `json:"read_bytes"`
	}
	if len(values) != 1 || len(values[0]) > 4096 || json.Unmarshal([]byte(values[0]), &receipt) != nil {
		p.add(&p.counts.invalid, 1)
	} else if rows, rowsOK := traceSourceNumber(receipt.Rows); rowsOK {
		if bytes, bytesOK := traceSourceNumber(receipt.Bytes); bytesOK {
			p.add(&p.counts.summaries, 1)
			p.add(&p.counts.rows, rows)
			p.add(&p.counts.bytes, bytes)
		} else {
			p.add(&p.counts.invalid, 1)
		}
	} else {
		p.add(&p.counts.invalid, 1)
	}
	if response.Body != nil {
		response.Body = &completeSourceReadBody{ReadCloser: response.Body, trace: p}
	}
	return response, nil
}

type completeSourceReadBody struct {
	io.ReadCloser
	trace *completeSourceReadTrace
}

func (b *completeSourceReadBody) Read(target []byte) (int, error) {
	n, err := b.ReadCloser.Read(target)
	b.trace.mu.Lock()
	if b.trace.active && n > 0 {
		b.trace.add(&b.trace.counts.body, uint64(n))
	}
	b.trace.mu.Unlock()
	return n, err
}
