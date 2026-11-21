// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

var irrSourceName = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,31}$`)

type irrSourceReceipt struct {
	Source       string    `json:"source"`
	GeneratedAt  time.Time `json:"generated_at"`
	SHA256       string    `json:"sha256"`
	Terms        string    `json:"terms"`
	RPKIFiltered bool      `json:"rpki_filtered"`
}

type irrLocalSource struct {
	irrSourceReceipt
	File string `json:"file"`
}

type irrLocalSnapshot struct {
	receipt    irrSourceReceipt
	validUntil time.Time
	objects    map[netip.Prefix][]irrRouteObject
}

func (s irrLocalSource) validate(now time.Time) error {
	rights, err := url.Parse(s.Terms)
	if !irrSourceName.MatchString(s.Source) || !filepath.IsLocal(s.File) || s.GeneratedAt.IsZero() || s.GeneratedAt.After(now) ||
		len(s.SHA256) != 64 || len(s.Terms) > 512 || err != nil || rights.Scheme != "https" || rights.Hostname() == "" ||
		rights.User != nil || rights.RawQuery != "" || rights.ForceQuery {
		return errIRRInput
	}
	return nil
}

// loadIRRLocalSource binds complete original bytes to the operator's source
// receipt. Rooted local paths keep the selected directory as the import scope.
func loadIRRLocalSource(ctx context.Context, root *os.Root, source irrLocalSource, now time.Time,
	maxAge time.Duration, memoryBytes, workUnits int64) (irrLocalSnapshot, error) {
	var empty irrLocalSnapshot
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	if err := source.validate(now); err != nil || root == nil || maxAge <= 0 {
		return empty, errIRRInput
	}
	if memoryBytes < 128<<10 || workUnits <= 0 {
		return empty, errIRRBudget
	}
	info, err := root.Stat(source.File)
	if err != nil || !info.Mode().IsRegular() {
		return empty, errIRRInput
	}
	file, err := root.Open(source.File)
	if err != nil {
		return empty, errIRRInput
	}
	defer func() { _ = file.Close() }()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || !os.SameFile(info, before) {
		return empty, errIRRInput
	}
	limit := min(memoryBytes/4, workUnits/4)
	if before.Size() <= 0 || before.Size() > limit {
		return empty, errIRRBudget
	}
	raw, err := io.ReadAll(io.LimitReader(file, before.Size()+1))
	if err != nil {
		return empty, errIRRInput
	}
	after, err := file.Stat()
	if err != nil || int64(len(raw)) != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) ||
		hex.EncodeToString(crypto.Hash(raw)) != source.SHA256 {
		return empty, errIRRInput
	}
	var input io.Reader = bytes.NewReader(raw)
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		archive, err := gzip.NewReader(input)
		if err != nil {
			return empty, errIRRInput
		}
		defer func() { _ = archive.Close() }()
		input = archive
		memoryBytes -= 64 << 10
	}
	objects, err := parseIRRRPSL(ctx, input, source.Source, source.GeneratedAt, memoryBytes-int64(len(raw))*2, workUnits-int64(len(raw))*2)
	if err != nil {
		return empty, err
	}
	return irrLocalSnapshot{receipt: source.irrSourceReceipt, validUntil: source.GeneratedAt.Add(maxAge).UTC(), objects: objects}, nil
}
