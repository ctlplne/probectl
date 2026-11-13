// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browsercanary

import (
	"errors"
	"strings"

	"github.com/ctlplne/probectl/internal/canary"
)

// ConfiguredResultTarget shares the producer's script parser. Both browser
// drivers report the original StartURL, including when later navigation or
// redirects move elsewhere. No worker, network request or artifact is opened.
func ConfiguredResultTarget(cfg canary.Config) (string, error) {
	target := strings.TrimSpace(cfg.Target)
	if cfg.Type != Type || target == "" {
		return "", errors.New("configured browser result identity is invalid")
	}
	script, err := scriptFromConfig(target, cfg.Params)
	if err != nil {
		return "", errors.New("configured browser script identity is invalid")
	}
	return script.StartURL, nil
}
