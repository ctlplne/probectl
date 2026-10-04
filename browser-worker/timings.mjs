// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// domTimings turns the raw navigation + paint entries read from the page into
// the reported DOM timing metrics (RTP-22). A paint metric is included only
// when the browser actually produced that paint entry; when it is missing the
// metric is OMITTED (not reported as a misleading 0 ms) and a reason flag is
// set, so a consumer can tell "painted at 0 ms" from "no paint observed".
export function domTimings(raw = {}) {
  const out = {
    dom_content_loaded_ms: Math.round(raw.domContentLoadedEventEnd || 0),
    load_ms: Math.round(raw.loadEventEnd || 0),
  }
  const paints = raw.paints || {}
  const fp = paints['first-paint']
  const fcp = paints['first-contentful-paint']
  if (typeof fp === 'number' && Number.isFinite(fp)) {
    out.first_paint_ms = Math.round(fp)
  }
  if (typeof fcp === 'number' && Number.isFinite(fcp)) {
    out.first_contentful_paint_ms = Math.round(fcp)
  }
  if (out.first_paint_ms === undefined && out.first_contentful_paint_ms === undefined) {
    out.paint_timing_unavailable = true
  }
  return out
}
