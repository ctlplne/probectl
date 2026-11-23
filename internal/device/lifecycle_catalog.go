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
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxDeviceLifecycleBytes = 16 << 20
	maxDeviceLifecycleRows  = 16384
)

var errDeviceLifecycleCatalog = errors.New("device lifecycle snapshot is incomplete or invalid")

type deviceLifecycleRecord struct {
	Manufacturer       string `json:"manufacturer"`
	Model              string `json:"model"`
	NoticeURL          string `json:"notice_url"`
	NoticePublishedAt  string `json:"notice_published_at"`
	EndOfSale          string `json:"end_of_sale,omitempty"`
	EndOfSecurityFixes string `json:"end_of_security_fixes,omitempty"`
	EndOfSupport       string `json:"end_of_support,omitempty"`
}

type deviceLifecycleKey struct {
	manufacturer, model string
}

type deviceLifecycleCatalog struct {
	observedAt time.Time
	byProduct  map[deviceLifecycleKey]deviceLifecycleRecord
}

func readDeviceLifecycleCatalog(input io.Reader) (*deviceLifecycleCatalog, error) {
	var snapshot struct {
		Version    int                     `json:"version"`
		ObservedAt string                  `json:"observed_at"`
		Records    []deviceLifecycleRecord `json:"records"`
	}
	content, err := io.ReadAll(io.LimitReader(input, maxDeviceLifecycleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxDeviceLifecycleBytes {
		return nil, errDeviceLifecycleCatalog
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, errDeviceLifecycleCatalog
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errDeviceLifecycleCatalog
	}
	observedAt, err := time.Parse(time.DateOnly, snapshot.ObservedAt)
	if err != nil || snapshot.Version != 1 || len(snapshot.Records) > maxDeviceLifecycleRows {
		return nil, errDeviceLifecycleCatalog
	}
	byProduct := make(map[deviceLifecycleKey]deviceLifecycleRecord, len(snapshot.Records))
	for _, record := range snapshot.Records {
		key := deviceLifecycleKey{manufacturer: record.Manufacturer, model: record.Model}
		if !validDeviceLifecycleRecord(record, observedAt) {
			return nil, errDeviceLifecycleCatalog
		}
		if prior, exists := byProduct[key]; exists && prior != record {
			return nil, errDeviceLifecycleCatalog
		}
		byProduct[key] = record
	}
	return &deviceLifecycleCatalog{observedAt: observedAt, byProduct: byProduct}, nil
}

func validDeviceLifecycleRecord(record deviceLifecycleRecord, observedAt time.Time) bool {
	if !validDeviceLifecycleName(record.Manufacturer) || !validDeviceLifecycleName(record.Model) {
		return false
	}
	link, err := url.Parse(record.NoticeURL)
	if err != nil || len(record.NoticeURL) > 1024 || link.Scheme != "https" || link.Hostname() == "" || link.User != nil {
		return false
	}
	publishedAt, err := time.Parse(time.DateOnly, record.NoticePublishedAt)
	if err != nil || publishedAt.After(observedAt) {
		return false
	}
	milestones := []string{record.EndOfSale, record.EndOfSecurityFixes, record.EndOfSupport}
	known := false
	for _, milestone := range milestones {
		if milestone == "" {
			continue
		}
		if _, err := time.Parse(time.DateOnly, milestone); err != nil {
			return false
		}
		known = true
	}
	return known
}

func validDeviceLifecycleName(name string) bool {
	return name != "" && len(name) <= 255 && utf8.ValidString(name) && name == strings.TrimSpace(name) &&
		strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) < 0
}

// lookup returns only a present, exact published product match. It keeps every
// original milestone and treats a missing or expired source as uncertain.
func (catalog *deviceLifecycleCatalog) lookup(manufacturer, model string, asOf time.Time, maxAge time.Duration) (deviceLifecycleRecord, bool) {
	if catalog == nil || asOf.IsZero() || maxAge <= 0 || catalog.observedAt.After(asOf) || asOf.Sub(catalog.observedAt) > maxAge {
		return deviceLifecycleRecord{}, false
	}
	record, present := catalog.byProduct[deviceLifecycleKey{manufacturer: strings.TrimSpace(manufacturer), model: strings.TrimSpace(model)}]
	return record, present
}
