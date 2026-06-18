// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

// DropStats is the typed loss ledger for the eBPF agent. Think of Dropped as
// the big red "some observations were lost" number, and these fields as the
// labels that explain which bucket overflowed.
type DropStats struct {
	DecodeFailures       uint64
	L4RingBufferFull     uint64
	L7RingBufferFull     uint64
	L7ActiveReadFailures uint64
	Other                uint64
}

// Total returns the aggregate dropped-record count represented by s.
func (s DropStats) Total() uint64 {
	return s.DecodeFailures + s.L4RingBufferFull + s.L7RingBufferFull + s.L7ActiveReadFailures + s.Other
}

// Add returns the field-wise sum of two cumulative snapshots.
func (s DropStats) Add(o DropStats) DropStats {
	return DropStats{
		DecodeFailures:       s.DecodeFailures + o.DecodeFailures,
		L4RingBufferFull:     s.L4RingBufferFull + o.L4RingBufferFull,
		L7RingBufferFull:     s.L7RingBufferFull + o.L7RingBufferFull,
		L7ActiveReadFailures: s.L7ActiveReadFailures + o.L7ActiveReadFailures,
		Other:                s.Other + o.Other,
	}
}

// Delta returns the positive field-wise movement from prev to s. If a source is
// restarted and a counter moves backwards, that field contributes zero for this
// sync and the caller's next baseline becomes the new lower value.
func (s DropStats) Delta(prev DropStats) DropStats {
	return DropStats{
		DecodeFailures:       positiveDelta(s.DecodeFailures, prev.DecodeFailures),
		L4RingBufferFull:     positiveDelta(s.L4RingBufferFull, prev.L4RingBufferFull),
		L7RingBufferFull:     positiveDelta(s.L7RingBufferFull, prev.L7RingBufferFull),
		L7ActiveReadFailures: positiveDelta(s.L7ActiveReadFailures, prev.L7ActiveReadFailures),
		Other:                positiveDelta(s.Other, prev.Other),
	}
}

func positiveDelta(cur, prev uint64) uint64 {
	if cur <= prev {
		return 0
	}
	return cur - prev
}

type dropStatsReporter interface {
	DropStats() DropStats
}

type dropCounter interface {
	Drops() uint64
}

func dropStatsFrom(src dropCounter) DropStats {
	if src == nil {
		return DropStats{}
	}
	if r, ok := src.(dropStatsReporter); ok {
		return r.DropStats()
	}
	return DropStats{Other: src.Drops()}
}
