// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Playwright serializes this function and initializes it before the top-level
// page's scripts. It returns only numeric observations from the current document.
export function installWebVitals() {
  if (window.top !== window || typeof PerformanceObserver !== "function") return;

  const observers = [];
  let hiddenAt = document.visibilityState === "hidden" ? 0 : Infinity;
  let lcp;
  let cls = 0;
  let sessionScore = 0;
  let sessionStart = -Infinity;
  let lastShift = -Infinity;
  let interactionOverflow = false;
  const interactions = new Map();

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") hiddenAt = Math.min(hiddenAt, performance.now());
  }, { capture: true });

  function observe(type, consume, options = {}) {
    if (!PerformanceObserver.supportedEntryTypes?.includes(type)) return false;
    const observer = new PerformanceObserver((entries) => consume(entries.getEntries()));
    try {
      observer.observe({ type, buffered: true, ...options });
    } catch {
      return false;
    }
    observers.push({ observer, consume });
    return true;
  }

  observe("largest-contentful-paint", (entries) => {
    for (const entry of entries) {
      const time = entry.startTime;
      if (time < hiddenAt && Number.isFinite(time) && time >= 0) lcp = Math.max(lcp ?? 0, time);
    }
  });
  const observesCLS = observe("layout-shift", (entries) => {
    for (const entry of entries) {
      if (entry.hadRecentInput || entry.startTime >= hiddenAt || !Number.isFinite(entry.value) || entry.value < 0) continue;
      if (entry.startTime - lastShift >= 1000 || entry.startTime - sessionStart >= 5000) {
        sessionStart = entry.startTime;
        sessionScore = 0;
      }
      lastShift = entry.startTime;
      sessionScore += entry.value;
      cls = Math.max(cls, sessionScore);
    }
  });
  observe("event", (entries) => {
    for (const entry of entries) {
      const { interactionId, duration, startTime } = entry;
      if (!(interactionId > 0) || startTime >= hiddenAt || !Number.isFinite(duration) || duration < 0) continue;
      if (interactions.size >= 512 && !interactions.has(interactionId)) {
        interactionOverflow = true;
        break;
      }
      interactions.set(interactionId, Math.max(interactions.get(interactionId) ?? 0, duration));
    }
  }, { durationThreshold: 16 });

  Object.defineProperty(window, "probectlSyntheticWebVitals", {
    value() {
      for (const { observer, consume } of observers) consume(observer.takeRecords());
      const result = {};
      if (lcp !== undefined) result.largest_contentful_paint_ms = lcp;
      const painted = performance.getEntriesByName("first-contentful-paint", "paint").some((entry) => entry.startTime < hiddenAt);
      if (observesCLS && painted) result.cumulative_layout_shift = cls;
      if (!interactionOverflow && interactions.size > 0) {
        const durations = [...interactions.values()].sort((a, b) => b - a);
        const count = performance.interactionCount;
        if (Number.isSafeInteger(count) && count >= interactions.size) {
          const rank = Math.floor(count / 50);
          if (rank < durations.length) result.interaction_to_next_paint_ms = durations[rank];
        }
      }
      return result;
    },
  });
}
