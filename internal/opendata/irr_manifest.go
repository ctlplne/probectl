// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

type irrManifest struct {
	Version int              `json:"version"`
	Sources []irrLocalSource `json:"sources"`
}

type IRRIndex struct {
	snapshots   []irrLocalSnapshot
	reviewAfter time.Duration
}

// LoadIRRIndex loads one immutable index for an operator-authorized set of
// local registry exports. A bad export leaves its source unavailable, while a
// malformed or ambiguous manifest cannot publish any source.
func LoadIRRIndex(ctx context.Context, path string, now time.Time, maxAge, reviewAfter time.Duration,
	memoryBytes, workUnits int64) (*IRRIndex, error) {
	const manifestLimit = 64 << 10
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxAge <= 0 || reviewAfter <= 0 || now.IsZero() {
		return nil, errIRRInput
	}
	if memoryBytes < manifestLimit || workUnits < manifestLimit {
		return nil, errIRRBudget
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	fileName := filepath.Base(path)
	info, err := root.Stat(fileName)
	if err != nil || !info.Mode().IsRegular() || info.Size() > manifestLimit {
		return nil, errIRRInput
	}
	file, err := root.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	reader := &io.LimitedReader{R: file, N: manifestLimit + 1}
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	var spec irrManifest
	if err := decoder.Decode(&spec); err != nil || spec.Version != 1 || len(spec.Sources) == 0 || len(spec.Sources) > 16 {
		return nil, errIRRInput
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || reader.N == 0 {
		return nil, errIRRInput
	}
	seen := make(map[string]bool, len(spec.Sources))
	for _, source := range spec.Sources {
		if err := source.validate(now); err != nil || seen[source.Source] {
			return nil, errIRRInput
		}
		seen[source.Source] = true
	}
	count := int64(len(spec.Sources))
	index := &IRRIndex{snapshots: make([]irrLocalSnapshot, 0, len(spec.Sources)), reviewAfter: reviewAfter}
	for _, source := range spec.Sources {
		snapshot, err := loadIRRLocalSource(ctx, root, source, now, maxAge, (memoryBytes-manifestLimit)/count, (workUnits-manifestLimit)/count)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			snapshot = irrLocalSnapshot{receipt: irrSourceReceipt{Source: source.Source}}
		}
		index.snapshots = append(index.snapshots, snapshot)
	}
	return index, nil
}

func (i *IRRIndex) Assess(ctx context.Context, prefix netip.Prefix, origin *uint32, at time.Time, budget int64) ([]IRRPosture, error) {
	if i == nil {
		return nil, ctx.Err()
	}
	rows := make([]IRRPosture, 0, len(i.snapshots))
	for _, source := range i.snapshots {
		posture, err := source.posture(ctx, prefix, origin, at, i.reviewAfter, budget/int64(len(i.snapshots)))
		if err != nil && !errors.Is(err, errIRRBudget) {
			return nil, err
		}
		rows = append(rows, posture)
	}
	return rows, ctx.Err()
}

func (*IRRIndex) Descriptor() Descriptor {
	return Descriptor{Name: "irr-local", Kind: Kind("irr"), AUP: AUP{License: "Operator-supplied per-registry terms", CommercialUse: CommercialUnknown}}
}

// An IP cannot identify a route object. Route assessments require the exact
// owned BGP prefix and origin after the caller's tenant and authority checks.
func (i *IRRIndex) Enrich(ctx context.Context, _ netip.Addr, _ *Enrichment) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := time.Now()
	for _, source := range i.snapshots {
		if source.objects != nil && !now.Before(source.receipt.GeneratedAt) && now.Before(source.validUntil) {
			return nil
		}
	}
	return errors.New("no complete current IRR snapshot")
}

func (en *Enricher) IRR() *IRRIndex {
	if en == nil {
		return nil
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	var found *IRRIndex
	for _, source := range en.sources {
		index, ok := source.src.(*IRRIndex)
		if !ok || !source.health.Enabled {
			continue
		}
		if found != nil {
			return nil
		}
		found = index
	}
	return found
}

var _ Source = (*IRRIndex)(nil)
