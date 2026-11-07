// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

var ErrIXMembershipBudget = errors.New("complete IX membership input exceeds resource admission")

// PeeringDBIXMemberships is a complete, operator-supplied local netixlan cache.
// It adds no downloader or tenant data. Source terms and explicit operator
// permission still apply; membership is neither a tenant grant nor a session.
type PeeringDBIXMemberships struct {
	snapshot IXMembershipSnapshot
	maxAge   time.Duration
}

type ixMembershipKey struct {
	asn       uint32
	ix, ixlan int64
}

type IXMembershipSnapshot struct {
	Version                string
	ObservedAt, ValidUntil time.Time
	Enabled, Current       bool
	byMember               map[ixMembershipKey][]string
}

type ixMembershipRecord struct {
	ID          int64  `json:"id"`
	IXID        int64  `json:"ix_id"`
	LANID       int64  `json:"ixlan_id"`
	ASN         uint32 `json:"asn"`
	Status      string `json:"status"`
	Operational bool   `json:"operational"`
}

func (r *ixMembershipRecord) UnmarshalJSON(raw []byte) error {
	type record ixMembershipRecord
	return strictIXJSON(raw, (*record)(r), []string{"id", "ix_id", "ixlan_id", "asn", "status", "operational"})
}

// LoadPeeringDBIXMemberships validates all rows before publishing any index.
// Byte-based admission covers the complete file, decoder, ID set and index;
// there is no independent membership or port count limit.
func LoadPeeringDBIXMemberships(ctx context.Context, path string, maxAge time.Duration, memoryBytes int64, now time.Time) (*PeeringDBIXMemberships, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxAge <= 0 || now.IsZero() {
		return nil, errors.New("IX membership freshness must be positive")
	}
	if memoryBytes < 4096 {
		return nil, ErrIXMembershipBudget
	}
	initial, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !initial.Mode().IsRegular() {
		return nil, errors.New("IX membership input must be a regular local file")
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
	if !before.Mode().IsRegular() {
		return nil, errors.New("IX membership input must be a regular local file")
	}
	limit := memoryBytes / 16
	if before.Size() > limit {
		return nil, ErrIXMembershipBudget
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrIXMembershipBudget
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(raw)) != after.Size() {
		return nil, errors.New("IX membership input changed during its complete read")
	}
	var manifest struct {
		Version     int                  `json:"version"`
		Object      string               `json:"object"`
		ObservedAt  time.Time            `json:"observed_at"`
		Complete    bool                 `json:"complete"`
		RecordCount int64                `json:"record_count"`
		Data        []ixMembershipRecord `json:"data"`
	}
	if err := strictIXJSON(raw, &manifest, []string{"version", "object", "observed_at", "complete", "record_count", "data"}); err != nil {
		return nil, err
	}
	if manifest.Version != 1 || manifest.Object != "netixlan" || !manifest.Complete || manifest.Data == nil || manifest.RecordCount != int64(len(manifest.Data)) || manifest.ObservedAt.IsZero() || manifest.ObservedAt.After(now) {
		return nil, errors.New("complete IX membership manifest and original observation time are required")
	}
	snapshot := IXMembershipSnapshot{Version: hex.EncodeToString(crypto.Hash(raw)), ObservedAt: manifest.ObservedAt.UTC(), ValidUntil: manifest.ObservedAt.Add(maxAge).UTC(), Enabled: true, byMember: map[ixMembershipKey][]string{}}
	ids := map[int64]bool{}
	remaining := memoryBytes - int64(len(raw))*8
	for _, row := range manifest.Data {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if remaining < 1024 {
			return nil, ErrIXMembershipBudget
		}
		remaining -= 1024
		if row.ID <= 0 || row.IXID <= 0 || row.LANID <= 0 || row.ASN == 0 || ids[row.ID] || (row.Status != "ok" && row.Status != "pending" && row.Status != "deleted") {
			return nil, errors.New("invalid or duplicate IX membership identity, ASN or status")
		}
		ids[row.ID] = true
		if row.Status != "ok" || !row.Operational {
			continue
		}
		key := ixMembershipKey{row.ASN, row.IXID, row.LANID}
		id := "peeringdb/netixlan/" + strconv.FormatInt(row.ID, 10) + "/snapshot/" + snapshot.Version
		snapshot.byMember[key] = append(snapshot.byMember[key], id)
	}
	return &PeeringDBIXMemberships{snapshot: snapshot, maxAge: maxAge}, nil
}

func (p *PeeringDBIXMemberships) Descriptor() Descriptor {
	d := peeringDBDescriptor()
	d.Name, d.Cadence = "peeringdb-ix-membership-file", p.maxAge
	return d
}

func (p *PeeringDBIXMemberships) availability(at time.Time) error {
	if !p.snapshot.Enabled || p.snapshot.ObservedAt.After(at) || !p.snapshot.ValidUntil.After(at) {
		return errors.New("complete local PeeringDB IX membership snapshot is unavailable or expired")
	}
	return nil
}

func (p *PeeringDBIXMemberships) Enrich(ctx context.Context, _ netip.Addr, _ *Enrichment) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.availability(time.Now())
}

// IXMemberships bypasses per-IP cache lifetime; disabled/stale input cannot
// establish current eligibility. A duplicate registered source is ambiguous.
func (en *Enricher) IXMemberships(at time.Time) IXMembershipSnapshot {
	if en == nil {
		return IXMembershipSnapshot{}
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	var out IXMembershipSnapshot
	found := false
	for _, source := range en.sources {
		p, ok := source.src.(*PeeringDBIXMemberships)
		if !ok {
			continue
		}
		if found {
			return IXMembershipSnapshot{Version: "ambiguous"}
		}
		found = true
		out = p.snapshot
		out.Enabled = source.health.Enabled && p.snapshot.Enabled
		out.Current = out.Enabled && p.availability(at) == nil
	}
	return out
}

func (s IXMembershipSnapshot) SameGeneration(other IXMembershipSnapshot) bool {
	return s.Version == other.Version && s.ObservedAt.Equal(other.ObservedAt) && s.ValidUntil.Equal(other.ValidUntil) && s.Enabled == other.Enabled && s.Current == other.Current
}

// Members returns complete copied public source IDs for one exact ASN/IX/LAN.
// The caller must first prove its tenant-owned interface/context eligibility.
// No public membership establishes that ownership, routing or a live session.
func (s IXMembershipSnapshot) Members(ctx context.Context, asn uint32, ixID, lanID, memoryBytes, workUnits int64) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if asn == 0 || ixID <= 0 || lanID <= 0 {
		return nil, errors.New("an exact IX membership selector is required")
	}
	if !s.Current {
		return nil, nil
	}
	values := s.byMember[ixMembershipKey{asn, ixID, lanID}]
	if memoryBytes <= 0 || workUnits <= 0 || int64(len(values)) > memoryBytes/32 || int64(len(values)) > workUnits/32 {
		return nil, ErrIXMembershipBudget
	}
	memoryBytes -= int64(len(values)) * 32
	for _, value := range values {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if int64(len(value)) > memoryBytes/2 {
			return nil, ErrIXMembershipBudget
		}
		memoryBytes -= int64(len(value)) * 2
	}
	return append([]string(nil), values...), nil
}

var _ Source = (*PeeringDBIXMemberships)(nil)

// Keep manifest JSON types in this source's strict decoder, not the shared
// enrichment result or a tenant-controlled API request.
var _ json.Unmarshaler = (*ixMembershipRecord)(nil)
