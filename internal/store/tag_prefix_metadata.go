// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"net/netip"

	"github.com/ctlplne/probectl/internal/tags"
)

func applyExplicitTagNetwork(subject *tags.Subject, network string) error {
	if network == "" {
		return nil
	}
	prefix, err := netip.ParsePrefix(network)
	if err != nil || subject.Kind != "prefix" {
		return tags.ErrInvalid
	}
	for _, observed := range subject.Prefixes {
		if observed != prefix {
			return ErrTagSubjectFactsAmbiguous
		}
	}
	subject.Prefixes = []netip.Prefix{prefix}
	return nil
}
