// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

const maxNVDFeedMetadataBytes = 8 << 10

type deviceNVDFeedMetadata struct {
	ModifiedAt time.Time
	Size       int64
	Digest     []byte
}

// readDeviceNVDFeedMetadata reads the sidecar accompanying an original NVD
// archive. Its size and digest describe the decompressed JSON document.
func readDeviceNVDFeedMetadata(input io.Reader) (deviceNVDFeedMetadata, error) {
	var metadata deviceNVDFeedMetadata
	body, err := io.ReadAll(io.LimitReader(input, maxNVDFeedMetadataBytes+1))
	if err != nil {
		return metadata, err
	}
	if len(body) > maxNVDFeedMetadataBytes {
		return metadata, errDeviceNVDCatalog
	}
	seen := make(map[string]bool, 5)
	for line := range strings.SplitSeq(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		field, value, separator := strings.Cut(line, ":")
		if !separator || seen[field] {
			return deviceNVDFeedMetadata{}, errDeviceNVDCatalog
		}
		seen[field] = true
		value = strings.TrimSpace(value)
		switch field {
		case "lastModifiedDate":
			metadata.ModifiedAt, err = time.Parse(time.RFC3339Nano, value)
		case "size":
			metadata.Size, err = strconv.ParseInt(value, 10, 64)
		case "sha256":
			metadata.Digest, err = hex.DecodeString(value)
		case "zipSize", "gzSize":
			_, err = strconv.ParseUint(value, 10, 64)
		default:
			return deviceNVDFeedMetadata{}, errDeviceNVDCatalog
		}
		if err != nil {
			return deviceNVDFeedMetadata{}, errDeviceNVDCatalog
		}
	}
	if !metadata.valid() {
		return deviceNVDFeedMetadata{}, errDeviceNVDCatalog
	}
	metadata.ModifiedAt = metadata.ModifiedAt.UTC()
	return metadata, nil
}

func (metadata deviceNVDFeedMetadata) valid() bool {
	return !metadata.ModifiedAt.IsZero() && metadata.Size > 0 && metadata.Size <= maxNVDFeedBytes && len(metadata.Digest) == 32
}

// readVerifiedDeviceNVDFeed builds a reference index from the same bytes the
// active crypto provider hashes. It publishes only after size, digest and JSON
// validation finish. The sidecar is a publisher checksum, with trust in its
// delivery coming from the operator's reference-data acquisition process.
func readVerifiedDeviceNVDFeed(ctx context.Context, input io.Reader, metadata deviceNVDFeedMetadata,
	products []nvdProductKey) (*deviceNVDCatalog, error) {
	if !metadata.valid() {
		return nil, errDeviceNVDCatalog
	}
	limited := &io.LimitedReader{R: input, N: metadata.Size + 1}
	reader, writer := io.Pipe()
	type hashResult struct {
		sum []byte
		err error
	}
	hashed := make(chan hashResult, 1)
	go func() {
		sum, err := crypto.HashReader(reader)
		_ = reader.CloseWithError(err)
		hashed <- hashResult{sum: sum, err: err}
	}()
	catalog, err := readDeviceNVDCatalog(ctx, io.TeeReader(limited, writer), products)
	_ = writer.CloseWithError(err)
	digest := <-hashed
	if err != nil {
		return nil, err
	}
	if digest.err != nil {
		return nil, digest.err
	}
	if limited.N != 1 || !bytes.Equal(digest.sum, metadata.Digest) {
		return nil, errDeviceNVDCatalog
	}
	catalog.sourceModifiedAt = metadata.ModifiedAt
	return catalog, nil
}
