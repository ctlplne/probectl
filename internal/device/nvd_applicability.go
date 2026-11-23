// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"regexp"
	"strconv"
	"strings"
)

type deviceCPE struct {
	part, vendor, product, version string
	numericOrder                   bool
}

type nvdDeviceCriterion struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdDeviceNode struct {
	Operator string               `json:"operator"`
	Negate   bool                 `json:"negate"`
	CPEMatch []nvdDeviceCriterion `json:"cpeMatch"`
}

var (
	plainNVDComponent = regexp.MustCompile(`^[a-z0-9_.-]{1,128}$`)
	numericNVDVersion = regexp.MustCompile(`^[0-9]{1,9}(\.[0-9]{1,9}){0,7}$`)
)

type nvdApplicability uint8

const (
	nvdUnknown nvdApplicability = iota
	nvdNoMatch
	nvdMatches
)

// matchDeviceNVDNode admits direct positive OR alternatives for one reviewed
// device CPE. A multiproduct dependency, negation, and unrecognized version
// scheme remain unknown in this projection.
func matchDeviceNVDNode(device deviceCPE, node nvdDeviceNode) nvdApplicability {
	if node.Operator != "OR" || node.Negate || len(node.CPEMatch) == 0 || len(node.CPEMatch) > 512 {
		return nvdUnknown
	}
	status := nvdNoMatch
	for _, entry := range node.CPEMatch {
		switch matchDeviceNVDCriterion(device, entry) {
		case nvdMatches:
			return nvdMatches
		case nvdUnknown:
			status = nvdUnknown
		}
	}
	return status
}

func matchDeviceNVDCriterion(device deviceCPE, entry nvdDeviceCriterion) nvdApplicability {
	if len(entry.Criteria) > 1024 {
		return nvdUnknown
	}
	name := strings.Split(entry.Criteria, ":")
	if len(name) != 13 || name[0] != "cpe" || name[1] != "2.3" {
		return nvdUnknown
	}
	if !plainNVDComponent.MatchString(name[2]) || !plainNVDComponent.MatchString(name[3]) || !plainNVDComponent.MatchString(name[4]) {
		return nvdUnknown
	}
	if name[2] != device.part || name[3] != device.vendor || name[4] != device.product {
		return nvdNoMatch
	}
	if !entry.Vulnerable || len(device.version) == 0 || name[5] == "-" {
		return nvdUnknown
	}
	for _, qualifier := range name[6:] {
		if qualifier != "*" {
			return nvdUnknown
		}
	}
	if name[5] != "*" {
		if !plainNVDComponent.MatchString(name[5]) {
			return nvdUnknown
		}
		if name[5] != device.version {
			return nvdNoMatch
		}
	}
	return compareDeviceNVDBounds(device, entry)
}

func compareDeviceNVDBounds(device deviceCPE, entry nvdDeviceCriterion) nvdApplicability {
	if entry.VersionStartIncluding != "" && entry.VersionStartExcluding != "" ||
		entry.VersionEndIncluding != "" && entry.VersionEndExcluding != "" {
		return nvdUnknown
	}
	bounds := []struct {
		version   string
		exclusive bool
		maximum   bool
	}{
		{entry.VersionStartIncluding, false, false},
		{entry.VersionStartExcluding, true, false},
		{entry.VersionEndIncluding, false, true},
		{entry.VersionEndExcluding, true, true},
	}
	for _, bound := range bounds {
		if bound.version == "" {
			continue
		}
		if !device.numericOrder {
			return nvdUnknown
		}
		order, known := compareDeviceNumericVersions(device.version, bound.version)
		if !known {
			return nvdUnknown
		}
		if order == 0 && bound.exclusive || order < 0 && !bound.maximum || order > 0 && bound.maximum {
			return nvdNoMatch
		}
	}
	return nvdMatches
}

func compareDeviceNumericVersions(a, b string) (int, bool) {
	if !numericNVDVersion.MatchString(a) || !numericNVDVersion.MatchString(b) {
		return 0, false
	}
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	// NVD range ordering is used only for equal-width numeric schemes. A
	// different component count can carry vendor-specific version meaning.
	if len(left) != len(right) {
		return 0, false
	}
	for index := range left {
		leftPart, leftErr := strconv.ParseUint(left[index], 10, 32)
		rightPart, rightErr := strconv.ParseUint(right[index], 10, 32)
		if leftErr != nil || rightErr != nil {
			return 0, false
		}
		switch {
		case leftPart < rightPart:
			return -1, true
		case leftPart > rightPart:
			return 1, true
		}
	}
	return 0, true
}
