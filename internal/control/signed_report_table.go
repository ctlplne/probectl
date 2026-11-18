// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/base64"
	"io"
	"strconv"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
)

// signedReportEvidenceTable places the same complete package into CSV rows
// and a PDF attachment. The caller owns the sealed package body.
func signedReportEvidenceTable(ctx context.Context, body *reporting.BodyStage, packageID, filename string, encoded reporting.CSVTable) (reporting.CSVTable, error) {
	receipt, err := body.Receipt(ctx)
	if err != nil {
		return reporting.CSVTable{}, err
	}
	// Bounded transfer chunks are not a population limit. Every byte of the
	// complete existing evidence envelope is included, in ordinal order. This
	// also avoids one enormous CSV/PDF cell for a month's original receipts.
	const chunkBytes = 12 << 10
	chunks := (receipt.Bytes + chunkBytes - 1) / chunkBytes
	encoded.Columns = plainClientReportColumns([]string{"package_id", "package_sha256", "package_bytes", "ordinal", "chunks", "signed_package_base64_chunk"})
	encoded.ExpectedRows = chunks
	encoded.PDFFile = &reporting.PDFJSONFile{Name: filename, Body: body}
	encoded.WalkRows = func(ctx context.Context, visit func([]string) error) error {
		if visit == nil {
			return store.ErrReportArtifactIntegrity
		}
		reader, err := body.Open(ctx)
		if err != nil {
			return err
		}
		defer reader.Close()
		buffer := make([]byte, chunkBytes)
		for ordinal := int64(0); ordinal < chunks; ordinal++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			n, err := io.ReadFull(reader, buffer)
			if err != nil && (err != io.ErrUnexpectedEOF || ordinal != chunks-1) {
				return err
			}
			if n <= 0 {
				return io.ErrUnexpectedEOF
			}
			if err := visit([]string{packageID, receipt.SHA256, strconv.FormatInt(receipt.Bytes, 10), strconv.FormatInt(ordinal, 10), strconv.FormatInt(chunks, 10), base64.StdEncoding.EncodeToString(buffer[:n])}); err != nil {
				return err
			}
		}
		var sentinel [1]byte
		if n, err := reader.Read(sentinel[:]); n != 0 || err != io.EOF {
			return store.ErrReportArtifactIntegrity
		}
		return ctx.Err()
	}
	return encoded, nil
}
