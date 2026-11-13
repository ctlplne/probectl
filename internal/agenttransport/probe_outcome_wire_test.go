// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestProbeOutcomeWireRefusesUnknownMetadataFields(t *testing.T) {
	if got, err := parseProbeOutcome(nil); err != nil || got != nil {
		t.Fatal("legacy absence acquired typed outcome authority", got, err)
	}
	raw := &agentv1.ProbeOutcome{Version: 1}
	raw.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
	if _, err := parseProbeOutcome(raw); status.Code(err) != codes.InvalidArgument {
		t.Fatal("unknown metadata accepted as complete current outcome", err)
	}
	raw = &agentv1.ProbeOutcome{Version: 2, HttpResponse: &agentv1.ProbeHttpResponse{StatusCode: 503, TlsVerified: true, SameOrigin: true}}
	got, err := parseProbeOutcome(raw)
	if err != nil || got.HTTPResponse == nil || got.HTTPResponse.StatusCode != 503 || !got.HTTPResponse.TLSVerified || !got.HTTPResponse.SameOrigin {
		t.Fatal("primary HTTP response was not decoded exactly", got, err)
	}
	raw.HttpResponse.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
	if _, err := parseProbeOutcome(raw); status.Code(err) != codes.InvalidArgument {
		t.Fatal("unknown nested HTTP metadata was accepted", err)
	}
}
