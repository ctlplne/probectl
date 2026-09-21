// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"os"
	"strings"
	"testing"

	cebpf "github.com/cilium/ebpf"
)

func TestL7RingBufferSpecFollowsConfig(t *testing.T) {
	spec := &cebpf.CollectionSpec{
		Maps: map[string]*cebpf.MapSpec{
			l7RingBufferMapName: {Type: cebpf.RingBuf, MaxEntries: 1 << 24},
		},
	}
	cfg := Default()
	cfg.L7RingBufferBytes = 20 << 20 // rounds up to 32 MiB

	applyL7RingBufferSpec(spec, cfg)

	if got, want := spec.Maps[l7RingBufferMapName].MaxEntries, uint32(32<<20); got != want {
		t.Fatalf("tls_chunks MaxEntries = %d, want %d", got, want)
	}
}

func TestL7RingBufferLiveLoaderResizesSpecBeforeLoad(t *testing.T) {
	src, err := os.ReadFile("source_live_l7_linux.go")
	if err != nil {
		t.Fatalf("read live L7 loader: %v", err)
	}
	text := string(src)
	for _, want := range []string{
		"loadSslsniff()",
		"applyL7RingBufferSpec(spec, cfg)",
		"spec.LoadAndAssign(&s.objs, nil)",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("live L7 loader missing %q; tls_chunks may no longer follow l7_ring_buffer_bytes", want)
		}
	}
	if strings.Contains(text, "loadSslsniffObjects(&s.objs") {
		t.Fatal("live L7 loader bypasses the collection spec resize path")
	}
}

func TestL7RingBufferSpecDefaultAndMissingMapAreSafe(t *testing.T) {
	spec := &cebpf.CollectionSpec{
		Maps: map[string]*cebpf.MapSpec{
			l7RingBufferMapName: {Type: cebpf.RingBuf},
		},
	}
	cfg := Default()
	cfg.L7RingBufferBytes = 0

	applyL7RingBufferSpec(spec, cfg)
	if got, want := spec.Maps[l7RingBufferMapName].MaxEntries, uint32(1<<24); got != want {
		t.Fatalf("default tls_chunks MaxEntries = %d, want %d", got, want)
	}

	applyL7RingBufferSpec(&cebpf.CollectionSpec{Maps: map[string]*cebpf.MapSpec{}}, cfg)
	applyL7RingBufferSpec(nil, cfg)
}

func TestL4RingBufferSpecStillFollowsConfig(t *testing.T) {
	spec := &cebpf.CollectionSpec{
		Maps: map[string]*cebpf.MapSpec{
			l4RingBufferMapName: {Type: cebpf.RingBuf, MaxEntries: 1 << 24},
		},
	}
	cfg := Default()
	cfg.RingBufferBytes = 8 << 20

	applyL4RingBufferSpec(spec, cfg)

	if got, want := spec.Maps[l4RingBufferMapName].MaxEntries, uint32(8<<20); got != want {
		t.Fatalf("events MaxEntries = %d, want %d", got, want)
	}
}
