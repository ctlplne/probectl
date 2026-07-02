// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
