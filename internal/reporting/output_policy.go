// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package reporting

import "errors"

// MaxBodyBytes is the format representation bound: an integer chunk ordinal
// addresses 2^31 chunks of BodyChunkBytes. It is not an allocation or default.
const MaxBodyBytes int64 = (1 << 31) * BodyChunkBytes

// OutputPolicy is operator admission, shared by generation and verified reads.
// Logical rows include an equal extra allowance for complete source metadata.
type OutputPolicy struct {
	CSVRows, PDFRows, Bytes int64
}

func DefaultOutputPolicy() OutputPolicy {
	return OutputPolicy{CSVRows: DefaultCSVLimits().TableRows, PDFRows: DefaultPDFLimits().TableRows, Bytes: DefaultCSVLimits().Bytes}
}

func (p OutputPolicy) Validate() error {
	maxRows := int64(^uint64(0)>>1) / 2
	if p.CSVRows <= 0 || p.CSVRows > maxRows || p.PDFRows <= 0 || p.PDFRows > maxRows || p.Bytes <= 0 || p.Bytes > MaxBodyBytes {
		return errors.New("report output admission must be positive and row/chunk representation safe")
	}
	return nil
}
