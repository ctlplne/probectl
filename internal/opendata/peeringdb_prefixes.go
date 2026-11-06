// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

var ErrIXPrefixBudget = errors.New("complete IX prefix input exceeds resource admission")

// PeeringDBIXPrefixes is an immutable operator-supplied LOCAL ixpfx cache.
// It never downloads data, sends tenant selectors or renews observation time.
// A complete replacement takes effect on restart, like other local sources.
// Source terms still apply; this is not permission to download or redistribute.
type PeeringDBIXPrefixes struct {
	snapshot IXPrefixSnapshot
	maxAge   time.Duration
}

type IXPrefix struct {
	SourceID string
	Prefix   netip.Prefix
}

// IXPrefixSnapshot contains public source metadata only. Its private index is
// immutable; callers can obtain only owned copies matched to their addresses.
// The tenant/RLS caller must authorize those addresses before invoking Match.
type IXPrefixSnapshot struct {
	Version                string
	ObservedAt, ValidUntil time.Time
	Enabled, Current       bool
	entries                []IXPrefix
}

type ixPrefixRecord struct {
	ID       int64      `json:"id"`
	LANID    int64      `json:"ixlan_id"`
	Protocol string     `json:"protocol"`
	Prefix   string     `json:"prefix"`
	Status   string     `json:"status"`
	Created  *time.Time `json:"created,omitempty"`
	Updated  *time.Time `json:"updated,omitempty"`
	InDFZ    *bool      `json:"in_dfz,omitempty"`
}

type ixPrefixManifest struct {
	Version     int              `json:"version"`
	Object      string           `json:"object"`
	ObservedAt  time.Time        `json:"observed_at"`
	Complete    bool             `json:"complete"`
	RecordCount int64            `json:"record_count"`
	Data        []ixPrefixRecord `json:"data"`
}

// Reject duplicate/unknown fields instead of letting the last key silently
// replace a completeness assertion. The schema is flat except the data array;
// nested records apply this same check independently during typed decoding.
func strictIXJSON(raw []byte, value any, required []string, optional ...string) error {
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("IX prefix object is required")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || seen[key] || !allowed[key] {
			return errors.New("duplicate or unknown IX prefix object field")
		}
		seen[key] = true
		var field json.RawMessage
		if err := d.Decode(&field); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(field), []byte("null")) {
			return errors.New("null IX prefix object field")
		}
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing IX prefix input")
	}
	for _, key := range required {
		if !seen[key] {
			return errors.New("missing IX prefix object field")
		}
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(value)
}
func (r *ixPrefixRecord) UnmarshalJSON(raw []byte) error {
	type record ixPrefixRecord
	return strictIXJSON(raw, (*record)(r), []string{"id", "ixlan_id", "protocol", "prefix", "status"}, "created", "updated", "in_dfz")
}

// LoadPeeringDBIXPrefixes admits the ENTIRE regular file plus decode/index
// workspace under the existing flow memory profile, with no row ceiling.
// Any malformed/partial/duplicate record refuses the complete index.
func LoadPeeringDBIXPrefixes(ctx context.Context, path string, maxAge time.Duration, memoryBytes int64, now time.Time) (*PeeringDBIXPrefixes, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maxAge <= 0 || now.IsZero() {
		return nil, errors.New("IX prefix freshness must be positive")
	}
	if memoryBytes < 4096 {
		return nil, ErrIXPrefixBudget
	}
	initial, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat local IX prefix file: %w", err)
	}
	if !initial.Mode().IsRegular() {
		return nil, errors.New("IX prefix input must be a regular local file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open local IX prefix file: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("IX prefix input must be a regular local file")
	}
	limit := memoryBytes / 16 // raw, strict decoder, typed rows, index, ID sets
	if info.Size() > limit {
		return nil, ErrIXPrefixBudget
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, ErrIXPrefixBudget
	}
	var manifest ixPrefixManifest
	if err := strictIXJSON(raw, &manifest, []string{"version", "object", "observed_at", "complete", "record_count", "data"}); err != nil {
		return nil, fmt.Errorf("decode complete IX prefix snapshot: %w", err)
	}
	if manifest.Version != 1 || manifest.Object != "ixpfx" || !manifest.Complete || manifest.Data == nil ||
		manifest.RecordCount != int64(len(manifest.Data)) || manifest.ObservedAt.IsZero() || manifest.ObservedAt.After(now) {
		return nil, errors.New("complete IX prefix manifest and explicit observation time are required")
	}
	s := IXPrefixSnapshot{Version: hex.EncodeToString(crypto.Hash(raw)), ObservedAt: manifest.ObservedAt.UTC(),
		ValidUntil: manifest.ObservedAt.Add(maxAge).UTC(), Enabled: true}
	ids, prefixes := map[int64]bool{}, map[netip.Prefix]bool{}
	used := int64(len(raw)) * 8
	for _, row := range manifest.Data {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		used += 1024 + int64(len(row.Prefix)+len(row.Protocol)+len(row.Status))*4
		if used > memoryBytes {
			return nil, ErrIXPrefixBudget
		}
		prefix, err := validateIXPrefixRecord(row, manifest.ObservedAt)
		if err != nil {
			return nil, err
		}
		if ids[row.ID] || prefixes[prefix] {
			return nil, errors.New("duplicate IX prefix identity or subnet")
		}
		ids[row.ID], prefixes[prefix] = true, true
		if row.Status != "ok" {
			continue
		}
		s.entries = append(s.entries, IXPrefix{Prefix: prefix,
			SourceID: "peeringdb/ixpfx/" + strconv.FormatInt(row.ID, 10) + "/ixlan/" + strconv.FormatInt(row.LANID, 10) + "/snapshot/" + s.Version})
	}
	return &PeeringDBIXPrefixes{snapshot: s, maxAge: maxAge}, nil
}

func validateIXPrefixRecord(row ixPrefixRecord, observed time.Time) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(row.Prefix)
	if err != nil || prefix != prefix.Masked() || prefix.String() != row.Prefix || prefix.Addr().Is4In6() ||
		prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() || row.ID <= 0 || row.LANID <= 0 ||
		(row.Protocol != "IPv4" && row.Protocol != "IPv6") || (prefix.Addr().Is4() != (row.Protocol == "IPv4")) ||
		(row.Status != "ok" && row.Status != "pending" && row.Status != "deleted") {
		return netip.Prefix{}, errors.New("invalid IX prefix object identity, protocol, status or canonical subnet")
	}
	for _, at := range []*time.Time{row.Created, row.Updated} {
		if at != nil && (at.IsZero() || at.After(observed)) {
			return netip.Prefix{}, errors.New("invalid IX prefix object observation clock")
		}
	}
	if row.Created != nil && row.Updated != nil && row.Created.After(*row.Updated) {
		return netip.Prefix{}, errors.New("IX prefix object clock runs backwards")
	}
	return prefix, nil
}

func (p *PeeringDBIXPrefixes) Descriptor() Descriptor {
	d := peeringDBDescriptor()
	d.Name, d.Cadence = "peeringdb-ix-prefix-file", p.maxAge
	return d
}
func (p *PeeringDBIXPrefixes) availability(at time.Time) error {
	if !p.snapshot.Enabled || p.snapshot.ObservedAt.After(at) || !p.snapshot.ValidUntil.After(at) {
		return errors.New("complete local PeeringDB IX prefix snapshot is unavailable or expired")
	}
	return nil
}
func (p *PeeringDBIXPrefixes) Enrich(ctx context.Context, _ netip.Addr, _ *Enrichment) error {
	// ixpfx gives LAN subnets, not ASN memberships. Never fabricate IXPs.
	if err := ctx.Err(); err != nil {
		return err
	}
	return p.availability(time.Now())
}

// IXPrefixes bypasses the generic per-IP enrichment cache: freshness and
// enabled state are checked on EVERY role operation, including frozen reads.
func (en *Enricher) IXPrefixes(at time.Time) IXPrefixSnapshot {
	if en == nil {
		return IXPrefixSnapshot{}
	}
	en.mu.Lock()
	defer en.mu.Unlock()
	var out IXPrefixSnapshot
	found := false
	for _, ms := range en.sources {
		p, ok := ms.src.(*PeeringDBIXPrefixes)
		if !ok {
			continue
		}
		if found {
			return IXPrefixSnapshot{Version: "ambiguous"}
		}
		found = true
		out = p.snapshot
		out.Enabled = ms.health.Enabled && p.snapshot.Enabled
		out.Current = out.Enabled && p.availability(at) == nil
	}
	return out
}

func (s IXPrefixSnapshot) SameGeneration(other IXPrefixSnapshot) bool {
	return s.Version == other.Version && s.ObservedAt.Equal(other.ObservedAt) && s.ValidUntil.Equal(other.ValidUntil) && s.Enabled == other.Enabled && s.Current == other.Current
}

func (s IXPrefixSnapshot) Match(ctx context.Context, addresses []netip.Addr, memoryBytes, workUnits int64) ([]IXPrefix, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.Current {
		return nil, nil
	}
	var out []IXPrefix
	for _, entry := range s.entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if workUnits <= 0 {
			return nil, ErrIXPrefixBudget
		}
		workUnits--
		matched := false
		for _, addr := range addresses {
			if workUnits <= 0 {
				return nil, ErrIXPrefixBudget
			}
			workUnits--
			if entry.Prefix.Contains(addr.Unmap()) {
				matched = true
			}
		}
		if !matched {
			continue
		}
		charge := int64(len(entry.SourceID)) + 256
		if memoryBytes < charge {
			return nil, ErrIXPrefixBudget
		}
		memoryBytes -= charge
		out = append(out, entry)
	}
	return out, nil
}
