// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"cmp"
	"strings"
	"unicode"
)

// ValidKubernetesResourceVersion excludes the server's arbitrary-cache
// selector. A confirmed inventory observation needs an exact resume version.
func ValidKubernetesResourceVersion(version string) bool {
	return version != "" && version != "0" && strings.IndexFunc(version, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) < 0
}

// CompareKubernetesResourceVersions compares versions from the same resource
// type and authorized kube-apiserver. Decimal versions have arbitrary width.
// Opaque versions can only be checked for equality.
func CompareKubernetesResourceVersions(a, b string) (int, bool) {
	if a == b {
		return 0, true
	}
	if !decimalKubernetesResourceVersion(a) || !decimalKubernetesResourceVersion(b) {
		return 0, false
	}
	if order := cmp.Compare(len(a), len(b)); order != 0 {
		return order, true
	}
	return strings.Compare(a, b), true
}

func decimalKubernetesResourceVersion(version string) bool {
	if version == "" || version[0] == '0' {
		return false
	}
	for _, digit := range version {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}
