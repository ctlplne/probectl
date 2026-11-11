// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
)

func FuzzDeviceCounterBatch(f *testing.F) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	raw, err := proto.Marshal(counterBatchFixture(tenant))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0xff, 0xff, 0x7f})
	f.Add(append(append([]byte{}, raw...), 0x98, 0x06, 1))
	f.Fuzz(func(t *testing.T, raw []byte) {
		const budget = 8 << 20
		got, err := ParseCounterBatch(t.Context(), tenant, raw, budget, budget)
		if err != nil {
			if got.Metrics != nil || got.Digest != ([32]byte{}) {
				t.Fatal("refused batch exposed partial counter data")
			}
			return
		}
		if len(got.Metrics) == 0 || uint64(len(got.Metrics)) != uint64(got.Input.PointCount) {
			t.Fatal("accepted an incomplete population")
		}
		var digest [32]byte
		copy(digest[:], crypto.Hash(raw))
		if got.Digest != digest {
			t.Fatal("accepted identity is not the original wire digest")
		}
		foreign := "66666666-6666-4666-8666-666666666666"
		if _, err := ParseCounterBatch(t.Context(), foreign, raw, budget, budget); err == nil {
			t.Fatal("raw tenant entered a foreign bus lane")
		}
		cancelled, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := ParseCounterBatch(cancelled, tenant, raw, budget, budget); err == nil {
			t.Fatal("cancelled admission succeeded")
		}
		for _, point := range got.Metrics {
			if point.TenantId != tenant || point.AgentId != got.Sender || point.DeviceAddress != got.Input.ConfiguredTarget || point.ExactCounter == nil {
				t.Fatal("whole source identity changed")
			}
		}
	})
}
