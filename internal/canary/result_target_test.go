// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary

import "testing"

func TestConfiguredResultTargetKeepsExecutableSelectorSemantics(t *testing.T) {
	for _, test := range []struct {
		config Config
		want   string
	}{
		{Config{Type: "http", Target: " https://reader:credential@example.test/check?version=two "}, "https://REDACTED:REDACTED@example.test/check?version=two"},
		{Config{Type: "tcp", Target: "2001:db8::1", Params: map[string]string{"port": "443"}}, "[2001:db8::1]:443"},
		{Config{Type: "udp", Target: "example.test:1234", Params: map[string]string{"port": "9999"}}, "example.test:1234"},
		{Config{Type: "voice", Target: "example.test", Params: map[string]string{"port": "16384"}}, "example.test:16384"},
		{Config{Type: "dns", Target: " Example.test. "}, "Example.test"},
		{Config{Type: "icmp", Target: "192.0.2.7"}, "192.0.2.7"},
		{Config{Type: "noop", Target: "operator-selector"}, "operator-selector"},
	} {
		got, err := ConfiguredResultTarget(test.config)
		if err != nil || got != test.want {
			t.Fatal("configuration target was confused with the producer's result identity", test.config.Type, got, test.want, err)
		}
	}
	for _, config := range []Config{{Type: "unknown", Target: "example.test"}, {Type: "http", Target: "https://credential@"}, {Type: "tcp", Target: "example.test"}, {Type: "dns", Target: " "}} {
		if target, err := ConfiguredResultTarget(config); err == nil || target != "" {
			t.Fatal("invalid or unsupported configuration invented an SLO selector", config.Type, target, err)
		}
	}
}
