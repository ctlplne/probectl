// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browser

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// ExecDriver runs a transaction by invoking an external worker process (the
// Playwright browser-worker under browser-worker/): it writes the Script JSON to
// the worker's stdin and parses the Result JSON from its stdout. Because it uses
// exec.CommandContext, a Fleet RunTimeout (ctx cancel) kills the worker process —
// real isolation for the heaviest canary. The worker provides full DOM/paint
// timings + a PNG screenshot that the HTTP driver cannot.
type ExecDriver struct {
	name string
	args []string
	env  []string
}

// NewExecDriver builds a driver that runs `name args...` per transaction (e.g.
// "node", "browser-worker/worker.mjs", or a container entrypoint).
func NewExecDriver(name string, args ...string) *ExecDriver {
	return &ExecDriver{name: name, args: args}
}

// WithEnv sets extra environment for the worker process (e.g. a step timeout).
func (d *ExecDriver) WithEnv(env ...string) *ExecDriver {
	d.env = append(d.env, env...)
	return d
}

func (*ExecDriver) Name() string { return "playwright" }

// workerResult is the worker's stdout contract. It embeds Result (whose JSON tags
// match the worker's fields) and adds the base64 screenshot.
type workerResult struct {
	Result
	ScreenshotB64         string `json:"screenshot_b64"`
	ScreenshotContentType string `json:"screenshot_content_type"`
}

func (d *ExecDriver) Run(ctx context.Context, s Script) (RunOutput, error) {
	scriptJSON, err := json.Marshal(s)
	if err != nil {
		return RunOutput{}, err
	}
	cmd := exec.CommandContext(ctx, d.name, d.args...)
	cmd.Stdin = bytes.NewReader(scriptJSON)
	if len(d.env) > 0 {
		cmd.Env = append(cmd.Environ(), d.env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	if err := cmd.Run(); err != nil {
		// A non-zero exit or a kill (ctx timeout) is an infrastructure fault → the
		// Fleet recycles the worker.
		return RunOutput{}, fmt.Errorf("browser worker: %w: %s", err, trimErr(stderr.String()))
	}

	var wr workerResult
	if err := json.Unmarshal(stdout.Bytes(), &wr); err != nil {
		return RunOutput{}, fmt.Errorf("browser worker: malformed result: %w", err)
	}

	res := wr.Result
	res.Script = s.Name
	res.Target = s.StartURL
	res.StartedAt = start
	if res.TotalMs == 0 {
		res.TotalMs = time.Since(start).Milliseconds()
	}

	var shot []byte
	if wr.ScreenshotB64 != "" {
		shot, _ = base64.StdEncoding.DecodeString(wr.ScreenshotB64)
	}
	ct := wr.ScreenshotContentType
	if ct == "" && len(shot) > 0 {
		ct = "image/png"
	}
	return RunOutput{Result: res, Screenshot: shot, ScreenshotType: ct}, nil
}

func trimErr(s string) string {
	if len(s) > 400 {
		return s[:397] + "..."
	}
	return s
}
