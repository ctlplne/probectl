// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Only the initial GET can be repeated. The caller runs operator steps after
// this returns; no action recipe, assertion or successful navigation is replayed.
// Keep one finite deadline, the same page/URL/trust, and at most two attempts.
export async function navigateInitialPage(
  page,
  url,
  timeout,
  absent = [],
  now = () => performance.now(),
) {
  if (!Number.isFinite(timeout) || timeout <= 0)
    throw new Error("Initial navigation requires a positive finite timeout");
  const deadline = now() + timeout;
  for (let attempt = 0; attempt < 2; attempt++) {
    const remaining = Math.floor(deadline - now());
    if (remaining <= 0)
      throw new Error("Initial navigation deadline exhausted");
    try {
      return await page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: remaining,
      });
    } catch (error) {
      if (attempt !== 0 || !String(error).includes("net::ERR_NETWORK_CHANGED"))
        throw error;
      const inspectionBudget = Math.floor(deadline - now());
      if (inspectionBudget <= 0) throw error;
      let text;
      try {
        text = await page
          .locator("body")
          .innerText({ timeout: Math.min(1000, inspectionBudget) });
      } catch {
        // A fresh blank page has not exposed an application document. A
        // committed but unreadable document cannot establish safe retry.
        if (page.url() !== "about:blank") throw error;
        text = "";
      }
      if (absent.some((forbidden) => text.includes(forbidden))) throw error;
    }
  }
  throw new Error("Initial navigation attempt budget exhausted");
}
