// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"time"
)

const (
	maxNVDFeedBytes   = 512 << 20
	maxNVDRecordBytes = 1 << 20
	maxNVDFeedRows    = 128000
	maxNVDIndexBytes  = 32 << 20
	maxNVDProducts    = 1024
)

var errDeviceNVDCatalog = errors.New("device NVD feed is incomplete or invalid")

type nvdProductKey struct{ part, vendor, product string }

type nvdDeviceConfiguration struct {
	Operator string          `json:"operator"`
	Negate   bool            `json:"negate"`
	Nodes    []nvdDeviceNode `json:"nodes"`
}

type nvdDeviceCVE struct {
	ID             string                   `json:"id"`
	Status         string                   `json:"vulnStatus"`
	Published      string                   `json:"published"`
	LastModified   string                   `json:"lastModified"`
	Configurations []nvdDeviceConfiguration `json:"configurations"`
}

type deviceNVDCatalog struct {
	observedAt       time.Time
	sourceModifiedAt time.Time
	byProduct        map[nvdProductKey][]*nvdDeviceCVE
}

type boundedNVDReader struct {
	ctx       context.Context
	input     io.Reader
	remaining int64
	record    int64
}

func (reader *boundedNVDReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	size := min(int64(len(buffer)), reader.remaining, reader.record)
	if size <= 0 {
		return 0, errDeviceNVDCatalog
	}
	read, err := reader.input.Read(buffer[:size])
	reader.remaining -= int64(read)
	reader.record -= int64(read)
	return read, err
}

// readDeviceNVDCatalog indexes only reviewed product keys from one complete
// local NVD JSON 2.0 feed. The reader supplies already decompressed bytes.
// Published record clocks and the feed timestamp stay independent.
func readDeviceNVDCatalog(ctx context.Context, input io.Reader, products []nvdProductKey) (*deviceNVDCatalog, error) {
	if len(products) == 0 || len(products) > maxNVDProducts {
		return nil, errDeviceNVDCatalog
	}
	productIndex := make(map[nvdProductKey][]*nvdDeviceCVE, len(products))
	for _, product := range products {
		if !validNVDProductKey(product) {
			return nil, errDeviceNVDCatalog
		}
		productIndex[product] = nil
	}
	catalog := &deviceNVDCatalog{byProduct: productIndex}
	reader := &boundedNVDReader{ctx: ctx, input: input, remaining: maxNVDFeedBytes + 1, record: maxNVDRecordBytes}
	decoder := json.NewDecoder(reader)
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errDeviceNVDCatalog
	}
	type metadata struct {
		format, version, timestamp string
		total, page, start         int
	}
	var meta metadata
	var rowCount int
	seen := make(map[string]bool, 7)
	for decoder.More() {
		reader.record = maxNVDRecordBytes
		token, err := decoder.Token()
		key, isKey := token.(string)
		if err != nil || !isKey || seen[key] {
			return nil, errDeviceNVDCatalog
		}
		seen[key] = true
		switch key {
		case "format":
			err = decoder.Decode(&meta.format)
		case "version":
			err = decoder.Decode(&meta.version)
		case "timestamp":
			err = decoder.Decode(&meta.timestamp)
		case "totalResults":
			err = decoder.Decode(&meta.total)
		case "resultsPerPage":
			err = decoder.Decode(&meta.page)
		case "startIndex":
			err = decoder.Decode(&meta.start)
		case "vulnerabilities":
			rowCount, err = catalog.readVulnerabilities(decoder, reader)
		default:
			return nil, errDeviceNVDCatalog
		}
		if err != nil {
			return nil, err
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || reader.remaining <= 0 ||
		len(seen) != 7 || meta.format != "NVD_CVE" || meta.version != "2.0" ||
		meta.start != 0 || meta.page < 0 || meta.total != rowCount {
		return nil, errDeviceNVDCatalog
	}
	reader.record = maxNVDRecordBytes
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errDeviceNVDCatalog
	}
	catalog.observedAt, err = parseDeviceNVDTime(meta.timestamp)
	if err != nil {
		return nil, errDeviceNVDCatalog
	}
	return catalog, ctx.Err()
}

func (catalog *deviceNVDCatalog) readVulnerabilities(decoder *json.Decoder, reader *boundedNVDReader) (int, error) {
	first, err := decoder.Token()
	if err != nil || first != json.Delim('[') {
		return 0, errDeviceNVDCatalog
	}
	seen := make(map[string]bool)
	var indexedBytes int64
	for decoder.More() {
		if len(seen) >= maxNVDFeedRows {
			return 0, errDeviceNVDCatalog
		}
		reader.record = maxNVDRecordBytes
		before := decoder.InputOffset()
		var entry struct {
			CVE *nvdDeviceCVE `json:"cve"`
		}
		if err := decoder.Decode(&entry); err != nil {
			return 0, err
		}
		size := decoder.InputOffset() - before
		if entry.CVE == nil || size > maxNVDRecordBytes || !deviceCVEIdentifier.MatchString(entry.CVE.ID) || seen[entry.CVE.ID] {
			return 0, errDeviceNVDCatalog
		}
		seen[entry.CVE.ID] = true
		if strings.EqualFold(entry.CVE.Status, "rejected") {
			continue
		}
		keys := catalog.trackedProducts(entry.CVE)
		if len(keys) == 0 {
			continue
		}
		published, publishErr := parseDeviceNVDTime(entry.CVE.Published)
		modified, modifyErr := parseDeviceNVDTime(entry.CVE.LastModified)
		if publishErr != nil || modifyErr != nil || modified.Before(published) || size > maxNVDIndexBytes-indexedBytes {
			return 0, errDeviceNVDCatalog
		}
		indexedBytes += size
		for key := range keys {
			catalog.byProduct[key] = append(catalog.byProduct[key], entry.CVE)
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim(']') {
		return 0, errDeviceNVDCatalog
	}
	return len(seen), nil
}

func (catalog *deviceNVDCatalog) trackedProducts(record *nvdDeviceCVE) map[nvdProductKey]bool {
	found := map[nvdProductKey]bool{}
	for _, config := range record.Configurations {
		for _, node := range config.Nodes {
			for _, criterion := range node.CPEMatch {
				chars := strings.SplitN(criterion.Criteria, ":", 6)
				if len(chars) != 6 || chars[0] != "cpe" || chars[1] != "2.3" {
					continue
				}
				key := nvdProductKey{chars[2], chars[3], chars[4]}
				if _, tracked := catalog.byProduct[key]; tracked {
					found[key] = true
				}
			}
		}
	}
	return found
}

func matchDeviceNVDConfiguration(device deviceCPE, config nvdDeviceConfiguration) nvdApplicability {
	if config.Negate || len(config.Nodes) == 0 || len(config.Nodes) > 64 ||
		(config.Operator != "OR" && (config.Operator != "" || len(config.Nodes) != 1)) {
		return nvdUnknown
	}
	result := nvdNoMatch
	for _, node := range config.Nodes {
		outcome := matchDeviceNVDNode(device, node)
		if outcome == nvdMatches {
			return nvdMatches
		}
		if outcome == nvdUnknown {
			result = nvdUnknown
		}
	}
	return result
}

func (catalog *deviceNVDCatalog) lookup(device deviceCPE, at time.Time, maxAge time.Duration) ([]nvdDeviceCVE, bool) {
	if catalog == nil || at.IsZero() || maxAge <= 0 || catalog.observedAt.After(at) ||
		at.Sub(catalog.observedAt) > maxAge || !plainNVDComponent.MatchString(device.version) {
		return nil, false
	}
	key := nvdProductKey{device.part, device.vendor, device.product}
	candidates, indexed := catalog.byProduct[key]
	if !indexed {
		return nil, false
	}
	var matches []nvdDeviceCVE
	comparable := true
	for _, entry := range candidates {
		status := nvdNoMatch
		for _, config := range entry.Configurations {
			verdict := matchDeviceNVDConfiguration(device, config)
			if verdict == nvdMatches {
				status = nvdMatches
				break
			}
			if verdict == nvdUnknown {
				status = nvdUnknown
			}
		}
		switch status {
		case nvdMatches:
			matches = append(matches, nvdDeviceCVE{
				ID: entry.ID, Status: entry.Status, Published: entry.Published, LastModified: entry.LastModified,
			})
		case nvdUnknown:
			comparable = false
		}
	}
	slices.SortFunc(matches, func(a, b nvdDeviceCVE) int { return strings.Compare(a.ID, b.ID) })
	return matches, comparable
}

func validNVDProductKey(key nvdProductKey) bool {
	return (key.part == "a" || key.part == "o" || key.part == "h") &&
		plainNVDComponent.MatchString(key.vendor) && plainNVDComponent.MatchString(key.product)
}

func parseDeviceNVDTime(raw string) (time.Time, error) {
	if at, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return at.UTC(), nil
	}
	return time.Parse("2006-01-02T15:04:05", raw)
}
