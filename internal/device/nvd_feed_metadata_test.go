// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestDeviceNVDFeedRefusesUnverifiedOriginalBytes(t *testing.T) {
	const raw = `{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","timestamp":"2026-10-21T18:40:00.000","vulnerabilities":[]}`
	metaBody := fmt.Sprintf("lastModifiedDate:2026-10-21T18:45:00Z\r\nsize:%d\r\ngzSize:82\r\nzipSize:130\r\nsha256:%x\r\n", len(raw), crypto.Hash([]byte(raw)))
	metadata, err := readDeviceNVDFeedMetadata(strings.NewReader(metaBody))
	if err != nil {
		t.Fatal(err)
	}
	products := []nvdProductKey{{"o", "owned", "release_os"}}
	catalog, err := readVerifiedDeviceNVDFeed(t.Context(), strings.NewReader(raw), metadata, products)
	if err != nil || !catalog.sourceModifiedAt.Equal(time.Date(2026, 10, 21, 18, 45, 0, 0, time.UTC)) ||
		catalog.sourceModifiedAt.Equal(catalog.observedAt) {
		t.Fatal("verified source metadata and feed clocks were not preserved independently", err)
	}
	for _, invalid := range []string{
		strings.Replace(raw, "18:40", "18:39", 1), raw + " ", raw[:len(raw)-1],
	} {
		if catalog, err := readVerifiedDeviceNVDFeed(t.Context(), strings.NewReader(invalid), metadata, products); err == nil || catalog != nil {
			t.Fatal("a different original byte sequence entered the index")
		}
	}
	if _, err := readDeviceNVDFeedMetadata(strings.NewReader(metaBody + "size:2\n")); err == nil {
		t.Fatal("duplicate sidecar authority was accepted")
	}
}
