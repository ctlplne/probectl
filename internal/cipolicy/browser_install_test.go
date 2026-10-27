// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"regexp"
	"strings"
	"testing"
)

// The integration receipt must use the same immutable Chromium payload as the
// browser-worker lane, without invoking the Node26-incompatible ZIP extractor.
func TestIntegrationBrowserPayloadStaysPinned(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	job := jobBlock(t, ci, "integration")
	browser := jobBlock(t, ci, "browser-worker")
	pin := regexp.MustCompile(`mcr\.microsoft\.com/playwright:v[0-9.]+-noble@sha256:[0-9a-f]{64}`).FindString(browser)
	if pin == "" || !strings.Contains(job, pin) {
		t.Fatal("integration must consume the worker's exact digest-pinned browser image")
	}
	for _, required := range []string{"docker create", "docker cp", ":/ms-playwright/.", "playwright install-deps chromium", "PLAYWRIGHT_BROWSERS_PATH=", "GITHUB_ENV", "fs.accessSync(chromium.executablePath()", "docker rm"} {
		if !strings.Contains(job, required) {
			t.Errorf("browser setup lacks %q", required)
		}
	}
	if regexp.MustCompile(`playwright install(?: |$)`).MatchString(job) {
		t.Error("integration reintroduced the hanging browser ZIP installer")
	}
	if !strings.Contains(job, `node-version: "26.12.1"`) {
		t.Error("browser setup must retain Node26")
	}
}
