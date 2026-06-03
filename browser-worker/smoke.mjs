// Real-browser smoke test (S36): start a tiny local login app, run worker.mjs in
// headless Chromium against it, and assert a scripted login reports step timings +
// a resource waterfall + DOM timings (success) and a failure screenshot (wrong
// password). Run in the Playwright CI container (browsers preinstalled):
//   npm ci && npm test
import { spawn } from "node:child_process";
import http from "node:http";

function assert(cond, msg) {
  if (!cond) {
    console.error("SMOKE FAIL:", msg);
    process.exit(1);
  }
}

function startApp() {
  const srv = http.createServer((req, res) => {
    // Serve real HTML so the browser builds a DOM (without a Content-Type the
    // browser renders the markup as plain text and the form inputs never exist).
    res.setHeader("content-type", "text/html; charset=utf-8");
    if (req.url.startsWith("/login")) {
      if (req.method === "GET") {
        res.end(`<form method=post action="/login">
          <input name=username><input name=password type=password>
          <button type=submit>Sign in</button></form>`);
        return;
      }
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        const p = new URLSearchParams(body);
        if (p.get("username") === "alice" && p.get("password") === "secret") {
          res.setHeader("set-cookie", "session=ok; Path=/");
          res.end("<h1>Welcome alice</h1>");
        } else {
          res.statusCode = 401;
          res.end("<h1>Invalid credentials</h1>");
        }
      });
      return;
    }
    res.statusCode = 404;
    res.end("nope");
  });
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => resolve(srv)));
}

function runWorker(script) {
  return new Promise((resolve, reject) => {
    const p = spawn("node", ["worker.mjs"], { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", () => {
      try {
        resolve(JSON.parse(out));
      } catch {
        reject(new Error("worker emitted non-JSON: " + out + " / stderr: " + err));
      }
    });
    p.stdin.write(JSON.stringify(script));
    p.stdin.end();
  });
}

const srv = await startApp();
const base = `http://127.0.0.1:${srv.address().port}`;
const steps = (password) => [
  { name: "open", action: "goto" },
  { name: "username", action: "fill", selector: "[name=username]", value: "alice" },
  { name: "password", action: "fill", selector: "[name=password]", value: password },
  { name: "submit", action: "click", selector: "button[type=submit]" },
  { name: "welcome", action: "assert_text", value: "Welcome" },
];

try {
  const ok = await runWorker({ name: "login", start_url: `${base}/login`, steps: steps("secret") });
  assert(ok.success === true, "login should succeed: " + JSON.stringify(ok));
  assert(Array.isArray(ok.steps) && ok.steps.length === 5, "expected 5 step results");
  assert(Array.isArray(ok.waterfall) && ok.waterfall.length >= 1, "expected a resource waterfall");
  assert(ok.dom && typeof ok.dom.load_ms === "number", "expected DOM timings");

  const bad = await runWorker({ name: "login", start_url: `${base}/login`, steps: steps("WRONG") });
  assert(bad.success === false, "wrong password should fail");
  assert(typeof bad.screenshot_b64 === "string" && bad.screenshot_b64.length > 0, "expected a failure screenshot");

  console.log("browser-worker smoke OK (success timings+waterfall+dom; failure screenshot)");
} finally {
  srv.close();
}
