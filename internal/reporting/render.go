// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package reporting renders bounded, self-contained tenant report artifacts.
// It intentionally has no network client: rendering cannot phone home.
package reporting

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"
)

const Banner = "probectl · tenant-scoped report"

type Document struct {
	Title               string
	Preset              string
	TenantName          string
	TenantScope         string
	AbsoluteFrom        time.Time
	AbsoluteTo          time.Time
	GeneratedAt         time.Time
	GeneratedBy         string
	Provenance          []string
	RedactionState      string
	CoverageLimitations []string
	Metrics             map[string]string
	Tables              []CSVTable
}

// Validate rejects incomplete/honesty-ambiguous documents before any artifact
// is stored. In particular, relative time words never substitute for an exact
// interval and reports cannot omit provenance/redaction/coverage disclosures.
func (d Document) Validate() error {
	if strings.TrimSpace(d.Title) == "" || strings.TrimSpace(d.TenantName) == "" || strings.TrimSpace(d.TenantScope) == "" {
		return fmt.Errorf("title, tenant name, and tenant scope are required")
	}
	if d.AbsoluteFrom.IsZero() || !d.AbsoluteTo.After(d.AbsoluteFrom) || d.GeneratedAt.IsZero() {
		return fmt.Errorf("a valid absolute time interval and generation time are required")
	}
	if len(d.Provenance) == 0 || strings.TrimSpace(d.RedactionState) == "" || len(d.CoverageLimitations) == 0 {
		return fmt.Errorf("provenance, redaction state, and coverage limitations are required")
	}
	if len(d.Metrics) > 100 {
		return fmt.Errorf("report metric count exceeds 100")
	}
	return nil
}

func RenderCSV(d Document) ([]byte, error) {
	return RenderCSVContext(context.Background(), d)
}

func RenderCSVContext(ctx context.Context, d Document) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := WriteCSV(ctx, &buf, d, DefaultCSVLimits()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
