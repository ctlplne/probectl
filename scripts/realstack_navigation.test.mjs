// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

import assert from "node:assert/strict";
import test from "node:test";
import { navigateInitialPage } from "./realstack_navigation.mjs";

const network = () => new Error("page.goto: net::ERR_NETWORK_CHANGED");
function fixture(
  outcomes,
  { text = "", unreadable = false, url = "about:blank" } = {},
) {
  const calls = [];
  let clock = 0;
  const page = {
    async goto(target, options) {
      calls.push({ target, options });
      clock += 7;
      const outcome = outcomes.shift();
      if (outcome instanceof Error) throw outcome;
      return outcome;
    },
    locator(selector) {
      assert.equal(selector, "body");
      return {
        async innerText(options) {
          assert.ok(options.timeout > 0 && options.timeout <= 1000);
          if (unreadable) throw new Error("document unavailable");
          return text;
        },
      };
    },
    url() {
      return url;
    },
  };
  return { page, calls, now: () => clock };
}

test("successful initial navigation executes once", async () => {
  const f = fixture(["response"]);
  assert.equal(
    await navigateInitialPage(
      f.page,
      "https://owned.example/ui/",
      100,
      [],
      f.now,
    ),
    "response",
  );
  assert.equal(f.calls.length, 1);
});
test("one network-change retry preserves URL and one deadline", async () => {
  const f = fixture([network(), "response"]);
  assert.equal(
    await navigateInitialPage(
      f.page,
      "https://owned.example/ui/",
      100,
      [],
      f.now,
    ),
    "response",
  );
  assert.deepEqual(f.calls, [
    {
      target: "https://owned.example/ui/",
      options: { waitUntil: "domcontentloaded", timeout: 100 },
    },
    {
      target: "https://owned.example/ui/",
      options: { waitUntil: "domcontentloaded", timeout: 93 },
    },
  ]);
});
test("TLS and other navigation errors never retry", async () => {
  for (const reason of [
    "net::ERR_CERT_AUTHORITY_INVALID",
    "net::ERR_CONNECTION_REFUSED",
    "navigation timeout",
  ]) {
    const error = new Error(reason),
      f = fixture([error, "unexpected"]);
    await assert.rejects(
      navigateInitialPage(f.page, "https://owned.example/ui/", 100, [], f.now),
      error,
    );
    assert.equal(f.calls.length, 1);
  }
});
test("a repeated network-change failure remains failure", async () => {
  const error = network(),
    f = fixture([network(), error]);
  await assert.rejects(
    navigateInitialPage(f.page, "https://owned.example/ui/", 100, [], f.now),
    error,
  );
  assert.equal(f.calls.length, 2);
});
test("the expired deadline cannot buy a second timeout", async () => {
  const f = fixture([network(), "unexpected"]);
  await assert.rejects(
    navigateInitialPage(f.page, "https://owned.example/ui/", 5, [], f.now),
    /ERR_NETWORK_CHANGED/,
  );
  assert.equal(f.calls.length, 1);
});
test("forbidden partial-page text is never retried away", async () => {
  const f = fixture([network(), "unexpected"], {
    text: "foreign tenant secret",
  });
  await assert.rejects(
    navigateInitialPage(
      f.page,
      "https://owned.example/ui/",
      100,
      ["foreign tenant"],
      f.now,
    ),
    /ERR_NETWORK_CHANGED/,
  );
  assert.equal(f.calls.length, 1);
});
test("an unreadable committed document fails closed", async () => {
  const f = fixture([network(), "unexpected"], {
    unreadable: true,
    url: "https://owned.example/ui/",
  });
  await assert.rejects(
    navigateInitialPage(f.page, "https://owned.example/ui/", 100, [], f.now),
    /ERR_NETWORK_CHANGED/,
  );
  assert.equal(f.calls.length, 1);
});
test("an uncommitted blank document may retry once", async () => {
  const f = fixture([network(), "response"], { unreadable: true });
  assert.equal(
    await navigateInitialPage(
      f.page,
      "https://owned.example/ui/",
      100,
      [],
      f.now,
    ),
    "response",
  );
  assert.equal(f.calls.length, 2);
});
test("missing finite time admission never starts navigation", async () => {
  for (const timeout of [0, -1, Infinity, NaN]) {
    const f = fixture(["unexpected"]);
    await assert.rejects(
      navigateInitialPage(
        f.page,
        "https://owned.example/ui/",
        timeout,
        [],
        f.now,
      ),
      /positive finite timeout/,
    );
    assert.equal(f.calls.length, 0);
  }
});
