// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"strings"
	"testing"
	"time"
)

// A post-shred attempt is hashed at write time from audit time (UTC) and
// re-hashed at verification from the timestamp Postgres hands back in the
// host's zone. The digest must not depend on the zone, or a control plane
// running outside UTC refuses its own ledger at startup.
func TestIRPostShredRecordDigestIsTheSameInEveryZone(t *testing.T) {
	at := time.Date(2026, 10, 9, 5, 2, 3, 123000, time.UTC)
	record := irPostShredRecord{
		TenantID: "6752bed5-7807-4e1a-92cd-d8e127a579fe", ChainPos: 1, AttemptAt: at,
		Operator: "op@msp.example", Surface: irPostShredSurface, Outcome: irPostShredOutcome,
		ProviderEventRef: strings.Repeat("a", 64),
	}
	written, err := irPostShredRecordDigest(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []*time.Location{time.FixedZone("EDT", -4*3600), time.FixedZone("IST", 5*3600+1800)} {
		record.AttemptAt = at.In(zone)
		if got, err := irPostShredRecordDigest(record); err != nil || got != written {
			t.Errorf("the digest of the same attempt read back in %s = %s (%v), want the written %s", zone, got, err, written)
		}
	}
}
