// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"bytes"
	"slices"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/twmb/franz-go/pkg/kgo"
)

// Exercise Kafka's real decompressor, including reuse after the adversarial
// two-block frame from the upstream advisory. No broker simulation can hide a
// panic behind a network error. Ordinary valid records must still round-trip.
// https://github.com/klauspost/compress/security/advisories/GHSA-fpmh-frq8-7rj8
func TestKafkaZstdTwoBlockFrameCannotPanicOrPoisonLaterRecords(t *testing.T) {
	frame := slices.Concat(
		[]byte{0x28, 0xb5, 0x2f, 0xfd, 0x00, 0x38, 0x74, 0x06, 0x00, 0x42, 0xb8, 0x32, 0x0d, 0x1a, 0x00, 0x00, 0x00, 0x90, 0xaf, 0xfa, 0xff, 0x03, 0x00, 0x80, 0xff, 0x7f},
		bytes.Repeat([]byte{0xa5, 0x94, 0x52, 0x4a, 0x29}, 37),
		[]byte{0xa5, 0x94, 0x12, 0x00, 0xad, 0x56, 0x03, 0xee, 0xff, 0xdf, 0xb3, 0x1a, 0x1c, 0x1a, 0x00, 0xe0, 0xff, 0x1f, 0x0f, 0xb1, 0x9c, 0x5a, 0xcf, 0x4d, 0xe4, 0x1d, 0x7b, 0xab, 0x99, 0x5e, 0x01, 0x51, 0xa4, 0x73, 0xd8, 0xb1, 0xf3, 0x39, 0x4b, 0x67, 0xf6, 0xab, 0x1a, 0xab, 0x1a, 0xab, 0x1a},
		bytes.Repeat([]byte{0x8c, 0x31, 0xc6, 0x18, 0x63}, 1365), []byte{0x8c, 0x31},
		bytes.Repeat([]byte{0x63, 0x8c, 0x31, 0xc6, 0x18}, 1365), []byte{0x63, 0x2c},
		bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365), []byte{0x31, 0x46},
		bytes.Repeat([]byte{0x31, 0xc6, 0x18, 0x63, 0x8c}, 1365), []byte{0x31, 0x06, 0x00},
	)
	decoder := kgo.DefaultDecompressor()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("Kafka zstd input panicked instead of a bounded decode result: %v", recovered)
		}
	}()
	// An upstream fix may accept a valid frame or reject it. Neither outcome
	// permits a process panic or stale decoder state in subsequent records.
	_, _ = decoder.Decompress(frame, 4)
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	for _, value := range []string{"tenant-a complete record", "tenant-b complete record"} {
		want := bytes.Repeat([]byte(value), 8192)
		got, err := decoder.Decompress(encoder.EncodeAll(want, nil), 4)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("Kafka zstd decoder corrupted a complete later record", err)
		}
	}
}
