// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bus

import (
	"errors"
	"strings"
	"testing"
)

// DPR-071: the async producer counts a record the broker rejected (e.g.
// MESSAGE_TOO_LARGE) long after Publish returned nil; producers read the
// counters through PublishFailureReporter to learn what was never delivered.
func TestKafkaPublishFailuresReportsAsyncRejections(t *testing.T) {
	k := &Kafka{}
	var _ PublishFailureReporter = k
	if f, s, last := k.PublishFailures(); f != 0 || s != 0 || last != nil {
		t.Fatalf("fresh bus reports failed=%d shed=%d last=%v", f, s, last)
	}
	k.failed.Add(2)
	k.shed.Add(1)
	k.recordFailure("probectl.t-acme.ebpf.flows", errors.New("MESSAGE_TOO_LARGE (uncompressed_bytes=1048600)"))
	f, s, last := k.PublishFailures()
	if f != 2 || s != 1 {
		t.Errorf("failed=%d shed=%d, want 2/1", f, s)
	}
	if last == nil || !strings.Contains(last.Error(), "probectl.t-acme.ebpf.flows") || !strings.Contains(last.Error(), "MESSAGE_TOO_LARGE") {
		t.Errorf("last failure must name the topic and the broker's reason, got %v", last)
	}
}
