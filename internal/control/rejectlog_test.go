// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// DPR-074: identical rejections replayed on every restart are logged once in
// full, counted inside the window, and summarized when the window turns; a
// different tuple is its own first occurrence.
func TestRejectionLoggerFoldsRepeatsIntoOneSummaryPerWindow(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	base := time.Date(2026, 9, 17, 9, 48, 58, 0, time.UTC)
	now := base
	rl := newRejectionLogger(time.Minute)
	rl.now = func() time.Time { return now }
	key := []string{"topology", "device", "tenant-a", "agent-1", "shared pooled lane is forbidden"}
	for i := 0; i < 17; i++ {
		rl.Log(log, "REJECTED batch", key, "view", "topology", "plane", "device")
		now = now.Add(time.Millisecond)
	}
	if n := strings.Count(buf.String(), "REJECTED batch"); n != 1 {
		t.Fatalf("17 identical rejections inside the window logged %d lines, want 1:\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "occurrences=1") {
		t.Fatalf("first occurrence must be logged in full:\n%s", buf.String())
	}
	rl.Log(log, "REJECTED batch", []string{"ndr", "ebpf", "tenant-a", "agent-2", "unknown agent"}, "view", "ndr")
	if n := strings.Count(buf.String(), "REJECTED batch"); n != 2 {
		t.Fatalf("a distinct tuple is its own first occurrence: %d lines", n)
	}
	now = base.Add(2 * time.Minute)
	rl.Log(log, "REJECTED batch", key, "view", "topology", "plane", "device")
	out := buf.String()
	if n := strings.Count(out, "REJECTED batch"); n != 3 {
		t.Fatalf("the window turning must emit one summary: %d lines", n)
	}
	if !strings.Contains(out, "suppressed_in_window=16") || !strings.Contains(out, "occurrences=17") {
		t.Fatalf("summary must carry the folded count:\n%s", out)
	}
}
