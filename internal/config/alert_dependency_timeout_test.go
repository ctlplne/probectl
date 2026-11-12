// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"testing"
	"time"
)

func TestDependencyPublicationTimeoutKeepsCompleteOperationAdmissionConfigurable(t *testing.T) {
	for _, item := range []struct {
		raw  string
		want time.Duration
	}{{"", 5 * time.Minute}, {"17m", 17 * time.Minute}, {"250ms", 250 * time.Millisecond}} {
		cfg, err := Load(envFunc(map[string]string{"PROBECTL_ALERT_DEPENDENCY_PUBLICATION_TIMEOUT": item.raw}))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.AlertDependencyPublicationTimeout != item.want {
			t.Fatal("complete dependency publication deadline changed", cfg.AlertDependencyPublicationTimeout, item.want)
		}
		if cfg.FlowQueryExecutionLimit != time.Minute {
			t.Fatal("dependency deadline changed a different operation's admission")
		}
	}
	for _, raw := range []string{"0s", "-1s", "unbounded", "999999999999999999h"} {
		if _, err := Load(envFunc(map[string]string{"PROBECTL_ALERT_DEPENDENCY_PUBLICATION_TIMEOUT": raw})); err == nil {
			t.Fatal("invalid dependency publication deadline was accepted", raw)
		}
	}
}
