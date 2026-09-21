// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import "time"

// StepResult is the outcome of one transaction step.
type StepResult struct {
	Name       string `json:"name,omitempty"`
	Action     Action `json:"action"`
	Success    bool   `json:"success"`
	DurationMs int64  `json:"duration_ms"`
	Detail     string `json:"detail,omitempty"` // error, matched text, or status
}

// ResourceTiming is one request in the page-load waterfall (resource timing).
type ResourceTiming struct {
	URL       string `json:"url"`
	Method    string `json:"method,omitempty"`
	Status    int    `json:"status,omitempty"`
	StartMs   int64  `json:"start_ms"` // offset from the transaction start
	DNSms     int64  `json:"dns_ms,omitempty"`
	ConnectMs int64  `json:"connect_ms,omitempty"`
	TLSms     int64  `json:"tls_ms,omitempty"`
	TTFBms    int64  `json:"ttfb_ms,omitempty"`
	TotalMs   int64  `json:"total_ms"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
}

// DOMTimings are the navigation/paint timings the browser driver captures (zero
// for the HTTP driver, which does not render).
type DOMTimings struct {
	DOMContentLoadedMs     int64 `json:"dom_content_loaded_ms,omitempty"`
	LoadMs                 int64 `json:"load_ms,omitempty"`
	FirstPaintMs           int64 `json:"first_paint_ms,omitempty"`
	FirstContentfulPaintMs int64 `json:"first_contentful_paint_ms,omitempty"`
}

// empty reports whether no DOM timings were captured.
func (d DOMTimings) empty() bool { return d == DOMTimings{} }

// ScreenshotRef points at the failure artifact in the object store.
type ScreenshotRef struct {
	Key         string `json:"key"`
	ContentType string `json:"content_type"`
	SizeBytes   int64  `json:"size_bytes"`
}

// Result is a complete transaction run.
type Result struct {
	Script     string           `json:"script"`
	TenantID   string           `json:"tenant_id,omitempty"`
	Target     string           `json:"target,omitempty"`
	Success    bool             `json:"success"`
	Error      string           `json:"error,omitempty"`
	StartedAt  time.Time        `json:"started_at"`
	TotalMs    int64            `json:"total_ms"`
	Steps      []StepResult     `json:"steps,omitempty"`
	Waterfall  []ResourceTiming `json:"waterfall,omitempty"`
	DOM        DOMTimings       `json:"dom,omitempty"`
	Screenshot *ScreenshotRef   `json:"screenshot,omitempty"`
}
