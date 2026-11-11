// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"testing"
	"time"
)

func TestCounterCaptureKeyBindsWholeOriginalPollAndStableReplay(t *testing.T) {
	tenant := "11111111-1111-4111-8111-111111111111"
	input := CounterCaptureInput{ConfiguredTarget: "192.0.2.9", PollStartedAt: time.Unix(1794000000, 123456789), PollCompletedAt: time.Unix(1794000002, 987654321), PointCount: 5001}
	digest := [32]byte{1, 2, 3}
	key, err := CounterCaptureKey(tenant, "same-agent", digest, input)
	if err != nil || key == ([32]byte{}) {
		t.Fatal("complete original counter poll could not be identified", err)
	}
	second, err := CounterCaptureKey(tenant, "same-agent", digest, input)
	if err != nil || second != key {
		t.Fatal("counter replay changed its immutable original key", err)
	}
	for _, change := range []func(*CounterCaptureInput){
		func(i *CounterCaptureInput) { i.ConfiguredTarget = "192.0.2.10" },
		func(i *CounterCaptureInput) { i.PollStartedAt = i.PollStartedAt.Add(time.Nanosecond) },
		func(i *CounterCaptureInput) { i.PollCompletedAt = i.PollCompletedAt.Add(time.Nanosecond) },
		func(i *CounterCaptureInput) { i.PointCount++ },
	} {
		other := input
		change(&other)
		got, err := CounterCaptureKey(tenant, "same-agent", digest, other)
		if err != nil || got == key || got == ([32]byte{}) {
			t.Fatal("counter key reused a different original source, clock or population", got, err)
		}
	}
	digest[31]++
	if got, err := CounterCaptureKey(tenant, "same-agent", digest, input); err != nil || got == key {
		t.Fatal("counter key ignored the complete original wire digest", err)
	}
}

func TestCounterCaptureKeySeparatesTenantsSendersAndRejectsUnboundInput(t *testing.T) {
	input := CounterCaptureInput{ConfiguredTarget: "192.0.2.9", PollStartedAt: time.Unix(1794000000, 0), PollCompletedAt: time.Unix(1794000001, 0), PointCount: 2}
	digest := [32]byte{1}
	first, err := CounterCaptureKey("11111111-1111-4111-8111-111111111111", "same-agent", digest, input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CounterCaptureKey("66666666-6666-4666-8666-666666666666", "same-agent", digest, input)
	if err != nil || first == second {
		t.Fatal("counter witness key crossed tenants sharing all producer values", err)
	}
	otherSender, err := CounterCaptureKey("11111111-1111-4111-8111-111111111111", "another-agent", digest, input)
	if err != nil || first == otherSender {
		t.Fatal("counter witness key replaced the authenticated sender with a shared source", err)
	}
	for _, tenant := range []string{"", "red", "00000000-0000-0000-0000-000000000000"} {
		if key, err := CounterCaptureKey(tenant, "same-agent", digest, input); err == nil || key != ([32]byte{}) {
			t.Fatal("unbound tenant received a counter witness key", tenant, err)
		}
	}
	for _, change := range []func(*CounterCaptureInput){
		func(i *CounterCaptureInput) { i.ConfiguredTarget = "" },
		func(i *CounterCaptureInput) { i.ConfiguredTarget = " 192.0.2.9" },
		func(i *CounterCaptureInput) { i.ConfiguredTarget = "invalid-\xff" },
		func(i *CounterCaptureInput) { i.PollStartedAt = time.Time{} },
		func(i *CounterCaptureInput) { i.PollCompletedAt = i.PollStartedAt.Add(-time.Nanosecond) },
		func(i *CounterCaptureInput) { i.PollCompletedAt = time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(i *CounterCaptureInput) { i.PointCount = 0 },
	} {
		bad := input
		change(&bad)
		if key, err := CounterCaptureKey("11111111-1111-4111-8111-111111111111", "same-agent", digest, bad); err == nil || key != ([32]byte{}) {
			t.Fatal("counter witness accepted malformed original input", err)
		}
	}
	if key, err := CounterCaptureKey("11111111-1111-4111-8111-111111111111", "same-agent", [32]byte{}, input); err == nil || key != ([32]byte{}) {
		t.Fatal("counter witness accepted a missing original digest", err)
	}
}
