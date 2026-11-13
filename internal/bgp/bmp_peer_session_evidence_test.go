// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
)

// Real TLS router/listener; the restricted evidence receiver is modeled.
func TestBMPPeerSessionKeepsEveryTransitionAndTenantOrigin(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"} {
		t.Run(tenant, func(t *testing.T) {
			calls := make(chan []entity.Observation, 8)
			stack := startBMPTestStack(t, WithBMPTenantLane(tenant, "same-lane"), WithBMPEntityEvidence("same-listener", capturedBMPEvidence{calls: calls}))
			defer stack.stop()
			cert, key, _ := stack.issue(tenant, "same-router", time.Hour)
			conn, err := stack.dial(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			up := observedPeerUpFrame(t, "192.0.2.7", 4294967295)
			for _, reason := range []byte{0, 4, 5, 0} {
				raw := append([]byte(nil), up...)
				state := "up"
				wantClaims := 2
				if reason != 0 {
					raw = append(raw[:48], reason)
					raw[5] = 2
					binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
					state = "down"
					wantClaims = 1
					if reason == 5 {
						state = "monitoring_withdrawn"
					}
				}
				if _, err := conn.Write(raw); err != nil {
					t.Fatal(err)
				}
				select {
				case got := <-calls:
					if len(got) != wantClaims {
						t.Fatal("down refreshed address identity or transition disappeared", len(got))
					}
					claim := got[len(got)-1]
					if claim.Source.AgentID != "same-listener" || claim.Source.SourceRef != "same-router" || claim.OriginSerial == "" || claim.BMPPeerSession == nil || claim.BMPPeerSession.State != state || !bytes.Equal(claim.BMPPeerSession.RawFrame, raw) {
						t.Fatal("original frame, source or lifecycle was changed")
					}
					if _, err := claim.Normalize(time.Now()); err != nil {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("stable identity cache suppressed a lifecycle event")
				}
			}
		})
	}
}
