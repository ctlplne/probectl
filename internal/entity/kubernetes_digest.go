// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
)

const (
	KubernetesInventoryRequestBytes    = 1 << 20
	KubernetesInventoryPartRows        = 64
	KubernetesInventoryGenerationBytes = 64 << 20
	KubernetesInventoryGenerationRows  = 1 << 18
)

// FrameKubernetesInventoryRecord length-prefixes a deterministic wire
// record. The sender and store both use it for the manifest and each part.
func FrameKubernetesInventoryRecord(wire []byte) io.Reader {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(wire)))
	return io.MultiReader(bytes.NewReader(size[:]), bytes.NewReader(wire))
}

// HashKubernetesInventory hashes the manifest and the ordered, already
// framed part stream without materializing an entire inventory enclosure.
func HashKubernetesInventory(manifest []byte, parts io.Reader) ([]byte, error) {
	const domain = "probectl/kubernetes-inventory/v1\x00"
	return crypto.HashReader(io.MultiReader(strings.NewReader(domain), FrameKubernetesInventoryRecord(manifest), parts))
}
