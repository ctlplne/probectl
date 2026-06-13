// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/pipeline"
)

// CORRECT-005 lane-coverage gate: every consumer that subscribes to a
// tenant-keyed topic must fan out across siloed-tenant lanes (implement
// pipeline.LaneFanout) rather than ship shared-only and silently miss siloed
// tenants. A NEW consumer added here that forgets WithNamespaceTenants/RunLanes
// fails to compile against this list — the regression guard the audit asked for.
func TestConsumersFanOutAcrossLanes(t *testing.T) {
	consumers := []any{
		(*SLOConsumer)(nil),
		(*CarbonConsumer)(nil),
	}
	for _, c := range consumers {
		if _, ok := c.(pipeline.LaneFanout); !ok {
			t.Fatalf("%T does not implement pipeline.LaneFanout — it would be blind to siloed tenants (CORRECT-005)", c)
		}
	}
}
