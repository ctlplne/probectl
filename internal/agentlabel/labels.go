// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package agentlabel validates operator-supplied agent placement metadata.
// Labels are local declarations, never inferred from IP addresses or fetched
// from an external geolocation service.
package agentlabel

import (
	"fmt"
	"strings"
	"unicode"
)

const (
	MaxLabels     = 32
	MaxKeyBytes   = 63
	MaxValueBytes = 128
)

// Normalize validates and trims a label map. Keys are canonicalized to lower
// case so the coverage query has one stable spelling for region and site.
func Normalize(in map[string]string) (map[string]string, error) {
	if len(in) > MaxLabels {
		return nil, fmt.Errorf("agent labels exceed limit %d", MaxLabels)
	}
	out := make(map[string]string, len(in))
	for rawKey, rawValue := range in {
		key := strings.ToLower(strings.TrimSpace(rawKey))
		value := strings.TrimSpace(rawValue)
		if key == "" || len(key) > MaxKeyBytes || !validKey(key) {
			return nil, fmt.Errorf("agent label key %q must be 1-%d characters using letters, digits, '.', '_', '-', or '/'", rawKey, MaxKeyBytes)
		}
		if value == "" || len(value) > MaxValueBytes {
			return nil, fmt.Errorf("agent label %q value must be 1-%d bytes", key, MaxValueBytes)
		}
		if _, duplicate := out[key]; duplicate {
			return nil, fmt.Errorf("agent label key %q is duplicated after normalization", key)
		}
		out[key] = value
	}
	return out, nil
}

func validKey(key string) bool {
	for _, r := range key {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		switch r {
		case '.', '_', '-', '/':
		default:
			return false
		}
	}
	return true
}
