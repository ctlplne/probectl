// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import assert from "node:assert/strict";
import { test } from "node:test";

import { domTimings } from "./timings.mjs";

// RTP-22: a missing paint entry must be omitted with a reason, not reported as
// a false 0 ms; a present paint entry is reported (positive).
test("omits paint metrics and flags a reason when no paint entries exist", () => {
  const t = domTimings({ domContentLoadedEventEnd: 120, loadEventEnd: 200, paints: {} });
  assert.equal(t.dom_content_loaded_ms, 120);
  assert.equal(t.load_ms, 200);
  assert.ok(!("first_paint_ms" in t), "first_paint_ms must be absent, not 0");
  assert.ok(!("first_contentful_paint_ms" in t), "first_contentful_paint_ms must be absent, not 0");
  assert.equal(t.paint_timing_unavailable, true);
});

test("reports paint metrics when the browser produced them", () => {
  const t = domTimings({
    domContentLoadedEventEnd: 100,
    loadEventEnd: 150,
    paints: { "first-paint": 42.6, "first-contentful-paint": 48.2 },
  });
  assert.equal(t.first_paint_ms, 43);
  assert.equal(t.first_contentful_paint_ms, 48);
  assert.ok(!("paint_timing_unavailable" in t));
});
