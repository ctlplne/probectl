// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

const (
	maxDeviceKEVBytes = 16 << 20
	maxDeviceKEVRows  = 20000
)

var (
	errDeviceKEVCatalog = errors.New("device KEV snapshot is incomplete or invalid")
	deviceCVEIdentifier = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)
)

type deviceKEVRecord struct {
	ID        string `json:"cveID"`
	DateAdded string `json:"dateAdded"`
	DueDate   string `json:"dueDate"`
}

type deviceKEVCatalog struct {
	released time.Time
	version  string
	entries  map[string]deviceKEVRecord
}

// readDeviceKEVCatalog reads the CISA JSON catalog already present on the
// deployment. Product applicability is established separately from NVD and
// original inventory. KEV supplies corroborating evidence for a CVE ID.
func readDeviceKEVCatalog(input io.Reader) (*deviceKEVCatalog, error) {
	var snapshot struct {
		Version         string            `json:"catalogVersion"`
		DateReleased    time.Time         `json:"dateReleased"`
		Count           int               `json:"count"`
		Vulnerabilities []deviceKEVRecord `json:"vulnerabilities"`
	}
	content, err := io.ReadAll(io.LimitReader(input, maxDeviceKEVBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxDeviceKEVBytes {
		return nil, errDeviceKEVCatalog
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, errDeviceKEVCatalog
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errDeviceKEVCatalog
	}
	if !validDeviceLifecycleName(snapshot.Version) || snapshot.DateReleased.IsZero() ||
		snapshot.Count != len(snapshot.Vulnerabilities) || snapshot.Count > maxDeviceKEVRows {
		return nil, errDeviceKEVCatalog
	}
	entries := make(map[string]deviceKEVRecord, snapshot.Count)
	for _, entry := range snapshot.Vulnerabilities {
		if _, duplicate := entries[entry.ID]; duplicate || !validDeviceKEVRecord(entry, snapshot.DateReleased) {
			return nil, errDeviceKEVCatalog
		}
		entries[entry.ID] = entry
	}
	return &deviceKEVCatalog{released: snapshot.DateReleased.UTC(), version: snapshot.Version, entries: entries}, nil
}

func validDeviceKEVRecord(entry deviceKEVRecord, released time.Time) bool {
	if !deviceCVEIdentifier.MatchString(entry.ID) {
		return false
	}
	added, err := time.Parse(time.DateOnly, entry.DateAdded)
	if err != nil || added.After(released) {
		return false
	}
	due, err := time.Parse(time.DateOnly, entry.DueDate)
	return err == nil && !due.Before(added)
}

func (catalog *deviceKEVCatalog) lookupApplicableCVE(id string, at time.Time, maxAge time.Duration) (deviceKEVRecord, bool) {
	if catalog == nil || maxAge <= 0 || catalog.released.After(at) || at.Sub(catalog.released) > maxAge {
		return deviceKEVRecord{}, false
	}
	entry, ok := catalog.entries[id]
	return entry, ok
}
