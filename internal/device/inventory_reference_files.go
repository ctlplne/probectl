// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

// DeviceInventoryReferenceFiles names optional operator-mounted snapshots.
// NVD requires both the publisher's sidecar and reviewed local CPE bindings.
type DeviceInventoryReferenceFiles struct {
	Lifecycle   string
	KEV         string
	NVD         string
	NVDMetadata string
	CPEBindings string
}

// DeviceInventoryReferences holds read-only reference indexes shared by all
// tenants. Lookup takes an already authorized row and performs no I/O.
type DeviceInventoryReferences struct {
	bindings  deviceCPEBindings
	lifecycle *deviceLifecycleCatalog
	kev       *deviceKEVCatalog
	nvd       *deviceNVDCatalog
}

// LoadDeviceInventoryReferences reads once at startup. A bad source is
// unavailable while other valid sources remain usable. The issue keys
// identify the affected sources without using local paths as labels.
func LoadDeviceInventoryReferences(ctx context.Context, files DeviceInventoryReferenceFiles) (*DeviceInventoryReferences, map[string]error) {
	references := new(DeviceInventoryReferences)
	issues := make(map[string]error)
	var err error
	references.lifecycle, err = readDeviceInventoryFile(files.Lifecycle, maxDeviceLifecycleBytes, readDeviceLifecycleCatalog)
	if err != nil {
		issues["lifecycle"] = err
	}
	references.kev, err = readDeviceInventoryFile(files.KEV, maxDeviceKEVBytes, readDeviceKEVCatalog)
	if err != nil {
		issues["kev"] = err
	}
	references.bindings, err = readDeviceInventoryFile(files.CPEBindings, maxCPEBindingBytes, readDeviceCPEBindings)
	if err != nil {
		issues["cpe_bindings"] = err
	}
	if files.NVD != "" || files.NVDMetadata != "" {
		references.nvd, err = loadDeviceInventoryNVD(ctx, files, references.bindings)
		if err != nil {
			issues["nvd"] = err
		}
	}
	return references, issues
}

func (references *DeviceInventoryReferences) Lookup(row entity.SNMPPhysicalComponent, now time.Time, maxAge time.Duration) DeviceInventoryReferenceFlags {
	if references == nil {
		return DeviceInventoryReferenceFlags{VulnerabilityCoverage: "unavailable"}
	}
	return inventoryReferenceFlags(row, references.bindings, references.lifecycle, references.nvd, references.kev, now, maxAge)
}

func loadDeviceInventoryNVD(ctx context.Context, files DeviceInventoryReferenceFiles, bindings deviceCPEBindings) (*deviceNVDCatalog, error) {
	if files.NVD == "" || files.NVDMetadata == "" || len(bindings) == 0 {
		return nil, errDeviceNVDCatalog
	}
	metadata, err := readDeviceInventoryFile(files.NVDMetadata, maxNVDFeedMetadataBytes, readDeviceNVDFeedMetadata)
	if err != nil {
		return nil, err
	}
	deduplicated := make(map[nvdProductKey]struct{})
	for _, fields := range bindings {
		for _, binding := range fields {
			deduplicated[nvdProductKey{binding.Part, binding.Vendor, binding.Product}] = struct{}{}
		}
	}
	products := make([]nvdProductKey, 0, len(deduplicated))
	for key := range deduplicated {
		products = append(products, key)
	}
	const maxArchiveBytes = maxNVDFeedBytes + 1<<20
	return readDeviceInventoryFile(files.NVD, maxArchiveBytes, func(input io.Reader) (*deviceNVDCatalog, error) {
		buffered := bufio.NewReader(input)
		magic, err := buffered.Peek(2)
		if err != nil {
			return nil, err
		}
		if magic[0] != 0x1f || magic[1] != 0x8b {
			return readVerifiedDeviceNVDFeed(ctx, buffered, metadata, products)
		}
		compressed, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, err
		}
		defer compressed.Close()
		return readVerifiedDeviceNVDFeed(ctx, compressed, metadata, products)
	})
}

// Only regular, bounded local files are accepted. A symlink in an
// operator-mounted directory may resolve to a regular file.
func readDeviceInventoryFile[T any](path string, maxBytes int64, read func(io.Reader) (T, error)) (T, error) {
	var zero T
	if path == "" {
		return zero, nil
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return zero, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBytes {
		return zero, errors.New("device reference input is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return zero, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return zero, err
	}
	if !opened.Mode().IsRegular() || opened.Size() > maxBytes || !os.SameFile(info, opened) {
		return zero, errors.New("device reference input changed while opening")
	}
	bounded := &io.LimitedReader{R: file, N: maxBytes + 1}
	result, err := read(bounded)
	if err == nil && bounded.N == 0 {
		return zero, errors.New("device reference input exceeded the file size limit")
	}
	return result, err
}
