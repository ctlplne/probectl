// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import cebpf "github.com/cilium/ebpf"

const (
	l4RingBufferMapName = "events"
	l7RingBufferMapName = "tls_chunks"
)

func applyL4RingBufferSpec(spec *cebpf.CollectionSpec, cfg *Config) {
	applyRingBufferSpec(spec, l4RingBufferMapName, cfg.RingBufferBytes)
}

func applyL7RingBufferSpec(spec *cebpf.CollectionSpec, cfg *Config) {
	applyRingBufferSpec(spec, l7RingBufferMapName, cfg.L7RingBufferBytes)
}

func applyRingBufferSpec(spec *cebpf.CollectionSpec, mapName string, bytes int) {
	if spec == nil || spec.Maps == nil {
		return
	}
	if m, ok := spec.Maps[mapName]; ok {
		m.MaxEntries = ringBufferBytes(bytes)
	}
}
