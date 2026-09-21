// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

type deadlineSignalConn struct {
	net.Conn
	set chan time.Time
}

func (c *deadlineSignalConn) SetDeadline(deadline time.Time) error {
	select {
	case c.set <- deadline:
	default:
	}
	return c.Conn.SetDeadline(deadline)
}

func TestBMPHandshakeDeadlineAppliedBeforePeerBytes(t *testing.T) {
	serverRaw, clientRaw := net.Pipe()
	probe := &deadlineSignalConn{
		Conn: serverRaw,
		set:  make(chan time.Time, 1),
	}
	server := tls.Server(probe, &tls.Config{})
	listener := NewBMPListener(nil, &capturePublisher{}, "test", discardLogger())
	done := make(chan error, 1)
	go func() { done <- listener.handleConn(context.Background(), server) }()

	var applied bool
	select {
	case deadline := <-probe.set:
		applied = !deadline.IsZero() && deadline.After(time.Now())
	case <-time.After(250 * time.Millisecond):
	}

	_ = clientRaw.Close()
	_ = serverRaw.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("BMP handshake did not stop after its test connection closed")
	}
	if !applied {
		t.Fatal("BMP listener began reading peer-controlled handshake bytes before applying a finite deadline")
	}
}
