// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browsercanary

import (
	"testing"

	"github.com/ctlplne/probectl/internal/canary"
)

func TestConfiguredBrowserResultTargetKeepsOriginalScriptSelector(t *testing.T) {
	for _, test := range []struct{ script, want string }{
		{"", "https://configured.example.test/"},
		{`{"name":"transaction","start_url":"https://original.example.test/","steps":[{"action":"goto","url":"https://later.example.test/"}]}`, "https://original.example.test/"},
		{`{"name":"transaction","steps":[{"action":"goto","url":"https://later.example.test/"}]}`, "https://configured.example.test/"},
	} {
		config := canary.Config{Type: Type, Target: " https://configured.example.test/ ", Params: map[string]string{ScriptParam: test.script}}
		got, err := ConfiguredResultTarget(config)
		if err != nil || got != test.want {
			t.Fatal("later navigation replaced the original producer identity", got, test.want, err)
		}
	}
}
