# Browser / transaction synthetic

## What it is

This is the canary that drives a **scripted multi-step transaction** — a login,
a checkout — and reports per-step timings, a page-load **waterfall**, DOM/paint
timings, and a **screenshot when it fails**. It's the heaviest test type
(running a real browser is expensive), so it runs as a managed worker fleet that
caps how many run at once, isolates each run, and recycles workers.

```mermaid
%%{init: {'theme':'base','themeVariables':{'background':'#0d1117','primaryColor':'#161b22','primaryTextColor':'#e6edf3','primaryBorderColor':'#3b82f6','lineColor':'#8b949e','secondaryColor':'#21262d','tertiaryColor':'#0d1117','clusterBkg':'#161b22','clusterBorder':'#30363d','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'},'flowchart':{'curve':'basis','nodeSpacing':55,'rankSpacing':55,'padding':12}}}%%
flowchart LR
  S[transaction script] --> F[Fleet: cap · isolate · recycle]
  F -->|Driver| H[HTTPDriver\nGo-native, real waterfall]
  F -->|Driver| P[Playwright worker\nfull DOM/paint + PNG]
  F -- failure artifact --> O[(object store\ntenant-prefixed)]
  F --> R[canary.Result → pipeline → TSDB / incidents]
```

## Two drivers, one contract

Both drivers implement the same `Script → Result` contract (the
`internal/browser.Driver` interface), so you can pick per deployment without
changing anything else:

| | **HTTPDriver** (default) | **Playwright worker** |
| - | ------------------------ | --------------------- |
| Runtime | Go-native, no browser | headless Chromium (`browser-worker/`) |
| Waterfall | real, per request (DNS / connect / TLS / TTFB / total) | real, per resource |
| DOM/paint timings | – | yes |
| Screenshot | the failed page's HTML body | a visual PNG |
| Runs | anywhere (incl. air-gapped, CI) | needs the Playwright image |

The HTTPDriver makes transaction monitoring available *everywhere* and is fully
unit-tested; the Playwright worker adds true rendering on top. The browser
rendering is delegated to a separate worker process (over the `ExecDriver`
contract) precisely to keep a whole browser *out* of probectl's single-binary
agent.

## Transaction script format

A script is JSON, parsed and validated by `internal/browser/script.go`:

```json
{
  "name": "login",
  "start_url": "https://app.example/login",
  "steps": [
    {"action": "goto"},
    {"action": "fill",   "selector": "[name=username]", "field": "username", "value": "alice"},
    {"action": "fill",   "selector": "[name=password]", "field": "password", "value": "secret"},
    {"action": "click",  "selector": "button[type=submit]"},
    {"action": "assert_text",   "value": "Welcome"},
    {"action": "assert_status", "status": 200}
  ]
}
```

The full action vocabulary: `goto`, `fill`, `click`, `submit`, `wait_text`,
`assert_text`, `assert_status`, `screenshot`. The two drivers read the fields
they each need — the browser driver uses `selector` (a DOM element), the HTTP
driver uses `field` (a form field name) plus `url` (the submit target).

## Result fields

Each run produces a `Result` (`internal/browser/result.go`): `success`/`error`,
`total_ms`, `steps[]` (each with name / action / success / duration),
`waterfall[]` (each request's url / method / status plus DNS / connect / TLS /
TTFB / total), `dom` (DOMContentLoaded / load / first-paint / first-contentful-
paint), and a `screenshot` reference. The run is then mapped onto the canonical
`canary.Result` (type `browser`), so it flows through the *same* pipeline → TSDB
/ incident path as every other canary: timings become metrics, and the
screenshot key becomes an attribute.

## Fleet: isolation, concurrency, recycling

Because browser workers are CPU- and memory-heavy, the `Fleet`
(`internal/browser/fleet.go`):

- **caps concurrency** — a worker pool of `MaxConcurrency`; extra runs block
  until a worker is free;
- **isolates each run** — a `RunTimeout` context bounds every run (default 60s);
  for the Playwright worker, a timeout *kills the worker process* (via
  `exec.CommandContext`);
- **recycles workers** — after `RecycleAfter` runs, or after any failed run, the
  driver is `Close()`d and rebuilt (this bounds resource leaks and restarts a
  crashed browser);
- **degrades safely** — a panicking run is caught and the worker recycled,
  rather than taking the fleet down.

## Screenshots → object store

A failure artifact is uploaded to the pluggable **object store**
(`internal/objectstore`) under a **tenant-prefixed key**
(`tenant/<id>/browser/<script>-<ts>.png`), so one tenant's artifacts are
isolated from another's at the storage layer. The store interface ships with a
filesystem implementation (the default) and an in-memory one (tests); an S3 /
MinIO implementation can slot in behind the same `Put`/`Get`/`Stat` interface
(the object store is pluggable per the PRD).

Successful runs store nothing by default (to bound storage); set
`StoreOnSuccess` to keep them. Object-lifecycle / retention policy is applied at
the store itself.

## Deploy

The Playwright worker ships as `browser-worker/` — a `Dockerfile` built on the
official Playwright image (Chromium + OS deps preinstalled), run as the image's
non-root `pwuser`. The worker reads one Script as JSON on stdin and writes the
Result as JSON on stdout; the fleet owns concurrency, isolation, and recycling.
Scale the worker fleet horizontally, separately from the control plane. CI runs
the worker's real-browser smoke test (a scripted login against a local app)
inside the Playwright image.

## Notes

- **Architecture choice.** The script format, result model, object-store upload,
  and fleet isolation/concurrency/recycling all live in Go (`internal/browser`,
  fully tested); only rendering is delegated to the external Playwright worker.
  This is what keeps browsers out of the single-binary agent.
- **Out of scope.** Real-user monitoring (RUM — see `docs/rum.md`) and endpoint
  browser-session capture are separate features. Note that some sites detect
  headless browsers; for those, configure a realistic user-agent / browser
  context.
