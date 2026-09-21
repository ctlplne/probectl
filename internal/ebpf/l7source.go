// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/ebpf/l7"
)

// L7Event is one captured plaintext chunk plus its connection context, delivered
// by the L7 capture layer (TLS-library uprobes / socket parsing). The endpoints
// are the connection's client→server orientation; the agent attributes the
// resulting calls to that edge regardless of which direction completed them.
type L7Event struct {
	ConnID      uint64
	TenantID    string
	Source      Endpoint
	Destination Endpoint
	Transport   string
	Encrypted   bool
	TLS         TLSMetadata
	Data        l7.DataEvent
}

// L7Source is a stream of L7Events. The live source is TLS-uprobe / socket
// capture (built only under -tags ebpf); the FixtureL7Source replays recorded
// events for CI and demos (the no-kernel path). Live sources may expose typed
// DropStats with kernel-side TLS ring/stash loss reasons.
type L7Source interface {
	L7Events(ctx context.Context) (<-chan L7Event, error)
	Drops() uint64
	Close() error
}

// FixtureL7Source replays L7 events from a recorded JSON file. Payloads are
// given as UTF-8 text (text protocols) or base64 (binary). Only request events
// need carry the connection's endpoints.
type FixtureL7Source struct {
	events []L7Event
}

type fixtureL7 struct {
	ConnID            uint64 `json:"conn_id"`
	TenantID          string `json:"tenant_id"`
	SrcAddress        string `json:"source_address"`
	SrcWorkload       string `json:"source_workload"`
	DstAddress        string `json:"destination_address"`
	DstWorkload       string `json:"destination_workload"`
	DstPort           uint32 `json:"destination_port"`
	Transport         string `json:"transport"`
	Encrypted         bool   `json:"encrypted"`
	TLSVisibility     string `json:"tls_visibility"`
	TLSVersion        string `json:"tls_version"`
	TLSCipher         string `json:"tls_cipher"`
	TLSServerName     string `json:"tls_server_name"`
	TLSPeerCertBase64 string `json:"tls_peer_certificate_der_base64"`
	TLSVerification   string `json:"tls_verification"`
	TLSConfidence     uint32 `json:"tls_confidence"`
	Kind              string `json:"kind"` // request | response
	OffsetMS          int64  `json:"time_offset_ms"`
	Text              string `json:"text"`
	Base64            string `json:"base64"`
}

// NewFixtureL7Source loads recorded L7 events from path.
func NewFixtureL7Source(path string) (*FixtureL7Source, error) {
	data, err := readFixtureFile(path)
	if err != nil {
		return nil, fmt.Errorf("ebpf: read l7 fixture: %w", err)
	}
	var recs []fixtureL7
	if err := json.Unmarshal(data, &recs); err != nil {
		return nil, fmt.Errorf("ebpf: parse l7 fixture: %w", err)
	}
	base := time.Unix(0, 0)
	events := make([]L7Event, 0, len(recs))
	for _, r := range recs {
		payload := []byte(r.Text)
		if r.Base64 != "" {
			if b, err := base64.StdEncoding.DecodeString(r.Base64); err == nil {
				payload = b
			}
		}
		kind := l7.Request
		if r.Kind == "response" {
			kind = l7.Response
		}
		var certDER []byte
		if r.TLSPeerCertBase64 != "" {
			decoded, err := base64.StdEncoding.DecodeString(r.TLSPeerCertBase64)
			if err != nil {
				return nil, fmt.Errorf("ebpf: parse l7 fixture tls certificate: %w", err)
			}
			certDER = decoded
		}
		events = append(events, L7Event{
			ConnID:      r.ConnID,
			TenantID:    r.TenantID,
			Source:      Endpoint{Address: r.SrcAddress, Workload: r.SrcWorkload},
			Destination: Endpoint{Address: r.DstAddress, Workload: r.DstWorkload, Port: r.DstPort},
			Transport:   orString(r.Transport, TransportTCP),
			Encrypted:   r.Encrypted,
			TLS: TLSMetadata{
				Visibility: r.TLSVisibility, Version: r.TLSVersion, Cipher: r.TLSCipher,
				ServerName: r.TLSServerName, PeerCertDER: certDER,
				Verification: r.TLSVerification, Source: "fixture",
				HandshakeAt: base.Add(time.Duration(r.OffsetMS) * time.Millisecond),
				Confidence:  r.TLSConfidence,
			},
			Data: l7.DataEvent{Kind: kind, Time: base.Add(time.Duration(r.OffsetMS) * time.Millisecond), Payload: payload},
		})
	}
	return &FixtureL7Source{events: events}, nil
}

// L7Events emits the recorded events once, then closes the channel.
func (s *FixtureL7Source) L7Events(ctx context.Context) (<-chan L7Event, error) {
	ch := make(chan L7Event)
	go func() {
		defer close(ch)
		for _, e := range s.events {
			select {
			case <-ctx.Done():
				return
			case ch <- e:
			}
		}
	}()
	return ch, nil
}

// Drops is always 0 for a fixture source.
func (s *FixtureL7Source) Drops() uint64 { return 0 }

// Close is a no-op for a fixture source.
func (s *FixtureL7Source) Close() error { return nil }

func orString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
