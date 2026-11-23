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
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

const (
	maxCPEBindingBytes                = 1 << 20
	maxInventoryVulnerabilityFindings = 32
)

var errDeviceCPEBindings = errors.New("device CPE bindings are incomplete or invalid")

type deviceCPEBinding struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	VersionField string `json:"version_field"`
	Part         string `json:"cpe_part"`
	Vendor       string `json:"cpe_vendor"`
	Product      string `json:"cpe_product"`
	VersionOrder string `json:"version_order"`
}

type deviceCPEBindings map[deviceLifecycleKey]map[string]deviceCPEBinding

func readDeviceCPEBindings(input io.Reader) (deviceCPEBindings, error) {
	content, err := io.ReadAll(io.LimitReader(input, maxCPEBindingBytes+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxCPEBindingBytes {
		return nil, errDeviceCPEBindings
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var snapshot struct {
		Version  int                `json:"version"`
		Bindings []deviceCPEBinding `json:"bindings"`
	}
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, errDeviceCPEBindings
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) || snapshot.Version != 1 || len(snapshot.Bindings) > maxNVDProducts {
		return nil, errDeviceCPEBindings
	}
	bindings := make(deviceCPEBindings)
	for _, row := range snapshot.Bindings {
		key := deviceLifecycleKey{row.Manufacturer, row.Model}
		if !validDeviceLifecycleName(row.Manufacturer) || !validDeviceLifecycleName(row.Model) ||
			!validNVDProductKey(nvdProductKey{row.Part, row.Vendor, row.Product}) ||
			(row.VersionField != "firmware" && row.VersionField != "software") ||
			(row.VersionOrder != "exact_only" && row.VersionOrder != "numeric_dot_equal_width") {
			return nil, errDeviceCPEBindings
		}
		if bindings[key] == nil {
			bindings[key] = make(map[string]deviceCPEBinding, 2)
		}
		if _, exists := bindings[key][row.VersionField]; exists {
			return nil, errDeviceCPEBindings
		}
		bindings[key][row.VersionField] = row
	}
	return bindings, nil
}

type DeviceInventoryLifecycleEvidence struct {
	ObservedAt string                `json:"source_date"`
	Notice     deviceLifecycleRecord `json:"notice"`
}

type DeviceInventoryVulnerabilityEvidence struct {
	ID            string    `json:"id"`
	VersionField  string    `json:"version_field"`
	ObservedValue string    `json:"observed_version"`
	NVDSource     string    `json:"nvd_source"`
	NVDObservedAt time.Time `json:"nvd_source_date"`
	NVDModifiedAt time.Time `json:"nvd_archive_modified_at,omitzero"`
	Published     string    `json:"published_at"`
	LastModified  string    `json:"last_modified_at"`
	KEVAdded      string    `json:"kev_added_at,omitempty"`
	KEVSource     string    `json:"kev_source,omitempty"`
	KEVObservedAt time.Time `json:"kev_source_date,omitzero"`
}

type DeviceInventoryReferenceFlags struct {
	Lifecycle                *DeviceInventoryLifecycleEvidence      `json:"lifecycle,omitempty"`
	VulnerabilityCoverage    string                                 `json:"vulnerability_coverage"`
	NVDSourceDate            time.Time                              `json:"nvd_source_date,omitzero"`
	NVDArchiveModifiedAt     time.Time                              `json:"nvd_archive_modified_at,omitzero"`
	VulnerabilitiesTruncated bool                                   `json:"vulnerabilities_truncated,omitempty"`
	Vulnerabilities          []DeviceInventoryVulnerabilityEvidence `json:"vulnerabilities,omitempty"`
}

// inventoryReferenceFlags enriches an already authorized component using only
// locally loaded reference snapshots and exact reviewed product bindings.
func inventoryReferenceFlags(row entity.SNMPPhysicalComponent, bindings deviceCPEBindings, lifecycle *deviceLifecycleCatalog,
	vulnerabilities *deviceNVDCatalog, exploited *deviceKEVCatalog, now time.Time, maxAge time.Duration) DeviceInventoryReferenceFlags {
	flags := DeviceInventoryReferenceFlags{VulnerabilityCoverage: "unavailable"}
	if notice, ok := lifecycle.lookup(row.Manufacturer, row.Model, now, maxAge); ok {
		flags.Lifecycle = &DeviceInventoryLifecycleEvidence{ObservedAt: lifecycle.observedAt.Format(time.DateOnly), Notice: notice}
	}
	product := deviceLifecycleKey{strings.TrimSpace(row.Manufacturer), strings.TrimSpace(row.Model)}
	selected := bindings[product]
	if vulnerabilities == nil || now.IsZero() || maxAge <= 0 || vulnerabilities.observedAt.After(now) ||
		now.Sub(vulnerabilities.observedAt) > maxAge || len(selected) == 0 {
		return flags
	}
	flags.VulnerabilityCoverage = "available"
	flags.NVDSourceDate = vulnerabilities.observedAt
	flags.NVDArchiveModifiedAt = vulnerabilities.sourceModifiedAt
	for _, candidate := range []struct{ field, version string }{{"firmware", row.Firmware}, {"software", row.Software}} {
		selection, configured := selected[candidate.field]
		if !configured {
			continue
		}
		cpe := deviceCPE{part: selection.Part, vendor: selection.Vendor, product: selection.Product,
			version: candidate.version, numericOrder: selection.VersionOrder == "numeric_dot_equal_width"}
		matches, comparable := vulnerabilities.lookup(cpe, now, maxAge)
		if !comparable {
			flags.VulnerabilityCoverage = "partial"
		}
		for _, match := range matches {
			finding := DeviceInventoryVulnerabilityEvidence{
				ID: match.ID, VersionField: candidate.field, ObservedValue: candidate.version,
				NVDSource: "https://nvd.nist.gov/vuln/detail/" + match.ID, NVDObservedAt: vulnerabilities.observedAt,
				NVDModifiedAt: vulnerabilities.sourceModifiedAt,
				Published:     match.Published, LastModified: match.LastModified,
			}
			if record, ok := exploited.lookupApplicableCVE(match.ID, now, maxAge); ok {
				finding.KEVAdded, finding.KEVSource, finding.KEVObservedAt =
					record.DateAdded, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", exploited.released
			}
			flags.Vulnerabilities = append(flags.Vulnerabilities, finding)
		}
	}
	if len(flags.Vulnerabilities) > maxInventoryVulnerabilityFindings {
		slices.SortStableFunc(flags.Vulnerabilities, func(left, right DeviceInventoryVulnerabilityEvidence) int {
			switch {
			case left.KEVAdded == "" && right.KEVAdded != "":
				return 1
			case left.KEVAdded != "" && right.KEVAdded == "":
				return -1
			default:
				return 0
			}
		})
		flags.Vulnerabilities = slices.Clone(flags.Vulnerabilities[:maxInventoryVulnerabilityFindings])
		flags.VulnerabilitiesTruncated = true
	}
	return flags
}
