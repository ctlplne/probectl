// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

import (
	"bytes"
	"testing"
)

func TestA2AFrameRoundTrip(t *testing.T) {
	key, err := a2aSessionKey("session-1")
	if err != nil {
		t.Fatal(err)
	}
	token := []byte("abcdefgh")
	req := encodeA2AReq(key, token, 9, 111)
	if len(req) != a2aReqLen {
		t.Fatalf("request length = %d, want %d", len(req), a2aReqLen)
	}
	if !verifyA2AMAC(key, a2aReqMACDomain, req, a2aReqBodyLen) {
		t.Fatal("request MAC did not verify")
	}
	reply := makeA2AReply(key, req[:a2aReqBodyLen], 222, 333)
	if len(reply) != a2aReplyLen {
		t.Fatalf("reply length = %d, want %d", len(reply), a2aReplyLen)
	}
	rep, ok := parseA2AReplyAuthenticated(key, reply)
	if !ok || !bytes.Equal(rep.token, token) || rep.seq != 9 || rep.t1 != 111 || rep.t2 != 222 || rep.t3 != 333 {
		t.Fatalf("parsed %+v ok=%v", rep, ok)
	}
	if _, ok := parseA2AReplyAuthenticated(key, reply[:10]); ok {
		t.Error("short authenticated buffer should not parse")
	}
}

func TestA2AFrameAuthenticationRejectsWrongKeyAndTampering(t *testing.T) {
	key, err := a2aSessionKey("session-good")
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := a2aSessionKey("session-bad")
	if err != nil {
		t.Fatal(err)
	}
	req := encodeA2AReq(key, []byte("abcdefgh"), 1, 123)
	if verifyA2AMAC(wrong, a2aReqMACDomain, req, a2aReqBodyLen) {
		t.Fatal("request verified with the wrong session key")
	}
	tampered := append([]byte(nil), req...)
	tampered[8] ^= 0xff
	if verifyA2AMAC(key, a2aReqMACDomain, tampered, a2aReqBodyLen) {
		t.Fatal("tampered request verified")
	}
	reply := makeA2AReply(key, req[:a2aReqBodyLen], 222, 333)
	if _, ok := parseA2AReplyAuthenticated(wrong, reply); ok {
		t.Fatal("reply parsed with the wrong session key")
	}
}

func TestStartA2AResponderRequiresSessionID(t *testing.T) {
	if _, err := StartA2AResponder("udp", "127.0.0.1", ""); err == nil {
		t.Fatal("responder without a session id must fail closed")
	}
}
