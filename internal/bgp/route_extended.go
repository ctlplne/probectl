// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
)

// parseBMPRouteUpdateFrame applies the actual receiving peer's RFC8654
// capability before complete framing. Advertising only on the sending side
// cannot authorize a message larger than4096 bytes. Loc-RIB uses the complete,
// identical fabricated OPEN pair required by RFC9069. Full65535-byte UPDATEs
// are accepted when permitted and admitted; OPEN's4096-byte wire limit stays.
// This does not interpret route attributes or establish a current source grant.
func parseBMPRouteUpdateFrame(ctx context.Context, raw []byte, source PeerUp, budget UpdateFrameBudget) (UpdateFrame, error) {
	if err := ctx.Err(); err != nil {
		return UpdateFrame{}, err
	}
	if source.SourceProfile.Format != "" && source.Header.View != BMPLocRIB {
		return UpdateFrame{}, ErrRouteCapabilities
	}
	// Reserve both complete OPEN decodes and their capability maps before they
	// allocate. Leave the independent UPDATE parser its complete own admission.
	openBytes := int64(len(source.SentOpen)) + int64(len(source.ReceivedOpen))
	if budget.MemoryBytes <= 1024 || budget.WorkUnits <= 0 || openBytes > (budget.MemoryBytes-1024)/128 || openBytes > budget.WorkUnits/8 {
		return UpdateFrame{}, ErrBGPUpdateFrameBudget
	}
	budget.MemoryBytes -= openBytes*128 + 1024
	budget.WorkUnits -= openBytes * 8
	sent, err := parseRouteOpenCapabilities(source.SentOpen, source.SourceProfile)
	if err != nil {
		return UpdateFrame{}, err
	}
	received, err := parseRouteOpenCapabilities(source.ReceivedOpen, source.SourceProfile)
	if err != nil {
		return UpdateFrame{}, err
	}
	var receiver routeOpenCapabilities
	switch source.Header.View {
	case BMPAdjRIBInPrePolicy, BMPAdjRIBInPostPolicy:
		receiver = sent
	case BMPAdjRIBOutPrePolicy, BMPAdjRIBOutPostPolicy:
		receiver = received
	case BMPLocRIB:
		if !sent.fourAS || !bytes.Equal(source.SentOpen, source.ReceivedOpen) {
			return UpdateFrame{}, ErrRouteCapabilities
		}
		receiver = sent
	default:
		return UpdateFrame{}, ErrRouteCapabilities
	}
	maximum := 4096
	if receiver.extended {
		maximum = 65535
	}
	if len(raw) > maximum {
		return UpdateFrame{}, ErrBGPUpdateFrame
	}
	return parseBGPUpdateFrame(ctx, raw, budget)
}
