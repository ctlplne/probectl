// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import "strings"

// NormalizeNetworkPrefix accepts only explicit operator metadata. A label is
// never passed here. Empty means absent/clear; identity aliases are unchanged.
func NormalizeNetworkPrefix(kind Kind, raw string) (string, error) {
	if len(raw) > 128 {
		return "", ErrInvalidClaim
	}
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	if kind != Prefix {
		return "", ErrInvalidClaim
	}
	alias, err := (AliasKey{Kind: PrefixAlias, Value: raw}).Normalize()
	if err != nil {
		return "", ErrInvalidClaim
	}
	return alias.Value, nil
}
