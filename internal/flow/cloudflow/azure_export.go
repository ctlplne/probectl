// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const maxAzureLogRecordBytes = 4 << 20

type azureLogRecordVisitor func(json.RawMessage) (int, error)

func scanAzureLogRecords(ctx context.Context, src io.Reader, provider Provider, visit azureLogRecordVisitor) (int, error) {
	bounded := &io.LimitedReader{R: src, N: maxPullBytes + 1}
	decoder := json.NewDecoder(bounded)
	bad, err := scanAzureLogObject(ctx, decoder, visit)
	if bounded.N == 0 {
		return bad, fmt.Errorf("cloudflow: %s object exceeds the decompressed export limit", provider)
	}
	if err != nil {
		return bad, fmt.Errorf("cloudflow: read %s export: %w", provider, err)
	}
	return bad, nil
}

func scanAzureLogObject(ctx context.Context, decoder *json.Decoder, visit azureLogRecordVisitor) (int, error) {
	if err := azureLogDelimiter(decoder, '{'); err != nil {
		return 0, err
	}
	var sawRecords bool
	var bad int
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return bad, err
		}
		if key != "records" {
			var ignored json.RawMessage
			if err := decoder.Decode(&ignored); err != nil {
				return bad, err
			}
			continue
		}
		if sawRecords {
			return bad, errors.New("duplicated records field")
		}
		sawRecords = true
		bad, err = scanAzureLogArray(ctx, decoder, visit)
		if err != nil {
			return bad, err
		}
	}
	if err := azureLogDelimiter(decoder, '}'); err != nil {
		return bad, err
	}
	if !sawRecords {
		return bad, errors.New("missing records array")
	}
	if _, err := decoder.Token(); err == nil {
		return bad, errors.New("extra data after the Azure flow log object")
	} else if !errors.Is(err, io.EOF) {
		return bad, err
	}
	return bad, nil
}

func scanAzureLogArray(ctx context.Context, decoder *json.Decoder, visit azureLogRecordVisitor) (int, error) {
	if err := azureLogDelimiter(decoder, '['); err != nil {
		return 0, err
	}
	var bad int
	var raw json.RawMessage
	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return bad, err
		}
		if err := decoder.Decode(&raw); err != nil {
			return bad, err
		}
		if visit != nil {
			skipped, err := visit(raw)
			bad += skipped
			if err != nil {
				return bad, err
			}
		}
	}
	return bad, azureLogDelimiter(decoder, ']')
}

func azureLogDelimiter(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != want {
		return fmt.Errorf("expected %q in Azure flow log object", want)
	}
	return nil
}
