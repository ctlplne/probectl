# browser-worker

The Playwright browser worker for probectl's browser/transaction synthetic. It
runs **one transaction script** in headless Chromium (Playwright `1.55.1`) and
emits a JSON `Result` — step timings, a resource waterfall, DOM/paint timings,
and a PNG screenshot on failure. probectl's `internal/browser` Fleet invokes it
(the `ExecDriver`), one process per run, and owns concurrency, per-run isolation
(it kills the process on timeout), and worker recycling.

## Contract

- **stdin**: the transaction Script JSON (`internal/browser/script.go`).
- **stdout**: the Result JSON (`step` results, `waterfall`, `dom`, `screenshot_b64`
  on failure) — parsed by `internal/browser/execdriver.go`.

## Run

```bash
npm install
echo '{"name":"login","start_url":"https://app.example/login","steps":[
  {"action":"goto"},
  {"action":"fill","selector":"[name=username]","value":"alice"},
  {"action":"fill","selector":"[name=password]","value":"secret"},
  {"action":"click","selector":"button[type=submit]"},
  {"action":"assert_text","value":"Welcome"}
]}' | node worker.mjs | jq .
```

`npm test` runs the real-browser smoke (`smoke.mjs`): a scripted login against a
local app, asserting success timings/waterfall/DOM and a failure screenshot.

## Container

`Dockerfile` builds on the official Playwright image (Chromium + OS deps
bundled), runs as the non-root `pwuser`, and uses `node worker.mjs` as the
entrypoint. This is the unit of the **browser fleet** — scale it horizontally; the
heavy CPU/memory lives here, away from the Go control plane and agents.

```bash
docker build -t probectl-browser-worker browser-worker/
echo '<script json>' | docker run -i --rm probectl-browser-worker
```

## Why a separate worker (not a compiled-in canary)

A browser is too heavy to compile into the single-binary agent. probectl keeps the
script format, result model, object-store upload, and fleet isolation/concurrency/
recycling in Go (`internal/browser`, fully unit-tested), and delegates rendering
to this worker over the `ExecDriver` contract. A lighter `HTTPDriver` (Go-native,
real HTTP-transaction waterfall, no rendering) is the default for environments
without a browser. See [`docs/browser-synthetic.md`](../docs/browser-synthetic.md).
