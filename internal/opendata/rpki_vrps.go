// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

var ErrRPKIVRPBudget = errors.New("complete RPKI input exceeds resource admission")

// RPKIVRP is an original validator assertion, including AS0 denial records.
// It is public data, never tenant identity, a route grant or a blocking action.
type RPKIVRP struct {
	Prefix    netip.Prefix `json:"prefix"`
	MaxLength int          `json:"max_length"`
	ASN       uint32       `json:"asn"`
}

type RPKISnapshot struct {
	Version                string
	ObservedAt, ValidUntil time.Time
	Enabled, Current       bool
	Records                int64
	byPrefix               map[netip.Prefix][]RPKIVRP
	complete               bool
}

type RPKIVRPs struct {
	snapshot RPKISnapshot
	maxAge   time.Duration
}

// LoadRPKIVRPs reads only an explicitly supplied regular local validator
// export. Every row, metadata value and EOF validates before any publication.
// Its digest and original generated clock cannot be renewed by copying a file.
func LoadRPKIVRPs(ctx context.Context, path string, maxAge time.Duration, memoryBytes, workUnits int64, now time.Time) (*RPKIVRPs, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if memoryBytes < 4096 || workUnits <= 0 {
		return nil, ErrRPKIVRPBudget
	}
	if maxAge <= 0 || now.IsZero() {
		return nil, errors.New("RPKI original-source freshness must be positive")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("RPKI export must be a regular local file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	limit := (memoryBytes - 4096) / 8
	if !before.Mode().IsRegular() || before.Size() > limit {
		return nil, ErrRPKIVRPBudget
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit || int64(len(raw)) > workUnits/8 {
		return nil, ErrRPKIVRPBudget
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(raw)) != after.Size() {
		return nil, errors.New("RPKI export changed during complete read")
	}
	budget := rpkiJSONBudget{memory: memoryBytes - int64(len(raw))*8 - 4096, work: workUnits - int64(len(raw))*8}
	snapshot, err := decodeRPKIExport(ctx, raw, &budget)
	if err != nil {
		return nil, err
	}
	if snapshot.ObservedAt.After(now) {
		return nil, errors.New("RPKI original generation time is in the future")
	}
	snapshot.Version, snapshot.Enabled = hex.EncodeToString(crypto.Hash(raw)), true
	if !snapshot.ObservedAt.IsZero() {
		snapshot.ValidUntil = snapshot.ObservedAt.Add(maxAge).UTC()
	}
	snapshot.Current = !snapshot.ObservedAt.IsZero() && snapshot.ValidUntil.After(now)
	return &RPKIVRPs{snapshot: snapshot, maxAge: maxAge}, nil
}

// Validate returns complete covering assertions and RFC6811's verdict. No
// fresh complete source or unique known origin means unknown, not not_found.
func (s RPKISnapshot) Validate(ctx context.Context, prefix netip.Prefix, origin *uint32, memoryBytes, workUnits int64) (string, []RPKIVRP, error) {
	if err := ctx.Err(); err != nil {
		return "unknown", nil, err
	}
	if !prefix.IsValid() || prefix != prefix.Masked() {
		return "unknown", nil, errors.New("canonical route prefix is required")
	}
	if !s.Enabled || !s.Current || !s.complete || origin == nil || *origin == 0 || *origin == 23456 {
		return "unknown", nil, nil
	}
	if memoryBytes < 4096 || workUnits < 4096 {
		return "unknown", nil, ErrRPKIVRPBudget
	}
	var count int64
	for bits := 0; bits <= prefix.Bits(); bits++ {
		if err := ctx.Err(); err != nil {
			return "unknown", nil, err
		}
		values := s.byPrefix[netip.PrefixFrom(prefix.Addr(), bits).Masked()]
		if int64(len(values)) > (memoryBytes-4096)/128-count || int64(len(values)) > (workUnits-4096)/128-count {
			return "unknown", nil, ErrRPKIVRPBudget
		}
		count += int64(len(values))
	}
	out := make([]RPKIVRP, 0, int(count))
	valid := false
	for bits := 0; bits <= prefix.Bits(); bits++ {
		for _, vrp := range s.byPrefix[netip.PrefixFrom(prefix.Addr(), bits).Masked()] {
			if err := ctx.Err(); err != nil {
				return "unknown", nil, err
			}
			out = append(out, vrp)
			valid = valid || (vrp.ASN != 0 && vrp.ASN == *origin && prefix.Bits() <= vrp.MaxLength)
		}
	}
	if count == 0 {
		return "not_found", out, nil
	}
	if valid {
		return "valid", out, nil
	}
	return "invalid", out, nil
}

func canonicalRPKIIndex(snapshot *RPKISnapshot) {
	for prefix, values := range snapshot.byPrefix {
		slices.SortFunc(values, func(a, b RPKIVRP) int {
			if a.MaxLength < b.MaxLength {
				return -1
			}
			if a.MaxLength > b.MaxLength {
				return 1
			}
			if a.ASN < b.ASN {
				return -1
			}
			if a.ASN > b.ASN {
				return 1
			}
			return 0
		})
		snapshot.byPrefix[prefix] = slices.Compact(values)
	}
}
