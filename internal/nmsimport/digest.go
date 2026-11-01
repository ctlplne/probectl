// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"strconv"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
)

// planDigest hashes normalized rows in global row-number order. Its memory
// stays constant as the source inventory grows. The storage layer still owns
// cross-page uniqueness through its composite row key and must finish capture
// before publishing a plan for apply. Raw source JSON never enters this hash.
type planDigest struct {
	sum     []byte
	nextRow int64
}

func newPlanDigest(tenantID, contextID, instanceRef, generationHash string,
	source Kind, policyVersion int) (*planDigest, error) {
	tenant, err := uuid.Parse(tenantID)
	if err != nil || tenant == uuid.Nil {
		return nil, ErrInvalidPage
	}
	context, err := uuid.Parse(contextID)
	if err != nil || context == uuid.Nil {
		return nil, ErrInvalidPage
	}
	if !safeInstanceRef(instanceRef) || !knownSource(source) ||
		len(generationHash) != 64 || !lowerHex(generationHash) ||
		policyVersion < 1 || policyVersion > math.MaxInt32 {
		return nil, ErrInvalidPage
	}
	header := "probectl:nms-plan:v1\x00" + tenant.String() + "\x00" + context.String() + "\x00" +
		string(source) + "\x00" + instanceRef + "\x00" + generationHash + "\x00" +
		strconv.Itoa(policyVersion)
	return &planDigest{sum: crypto.Default.Hash([]byte(header))}, nil
}

// appendPage commits its hash update only if every row follows the prior
// page. A failed page cannot leave a partial digest that apply would accept.
func (d *planDigest) appendPage(rows []planRow) error {
	if d == nil || len(d.sum) == 0 {
		return ErrInvalidPage
	}
	sum, next := append([]byte(nil), d.sum...), d.nextRow
	for _, row := range rows {
		if next == math.MaxInt64 || row.RowNumber != next {
			return ErrInvalidPage
		}
		wire, err := json.Marshal(row)
		if err != nil {
			return ErrInvalidPage
		}
		material := make([]byte, 0, len(sum)+1+len(wire))
		material = append(material, sum...)
		material = append(material, 0)
		material = append(material, wire...)
		sum = crypto.Default.Hash(material)
		next++
	}
	d.sum, d.nextRow = sum, next
	return nil
}

func (d *planDigest) hexSum() (string, error) {
	if d == nil || len(d.sum) == 0 {
		return "", ErrInvalidPage
	}
	return hex.EncodeToString(d.sum), nil
}
