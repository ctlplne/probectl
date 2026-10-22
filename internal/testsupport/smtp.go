// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsupport

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// SMTPMessage is one message an SMTPServer accepted.
type SMTPMessage struct {
	From string   // MAIL FROM address
	To   []string // RCPT TO addresses
	Data string   // the message, headers and body, dot-unstuffed
	User string   // the AUTH PLAIN identity the session authenticated as
	TLS  bool     // whether the session was TLS-secured when MAIL FROM arrived
}

// SMTPServer is a small loopback mail relay for receipts that deliver real
// alert mail: it offers STARTTLS, accepts AUTH PLAIN for its one user only
// after the session is secured, refuses MAIL FROM on a plaintext session, and
// records every accepted message. It is a test harness, never linked into a
// product binary.
type SMTPServer struct {
	Addr string

	ln       net.Listener
	tlsCfg   *tls.Config
	user     string
	password string

	mu       sync.Mutex
	messages []SMTPMessage
	refused  []string
}

// StartSMTPServer listens on 127.0.0.1 and serves until the test ends. A
// non-empty user requires AUTH PLAIN with that user and password before MAIL.
func StartSMTPServer(t *testing.T, tlsCfg *tls.Config, user, password string) *SMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &SMTPServer{Addr: ln.Addr().String(), ln: ln, tlsCfg: tlsCfg, user: user, password: password}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.session(conn)
		}
	}()
	return s
}

// Messages returns a copy of every accepted message.
func (s *SMTPServer) Messages() []SMTPMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SMTPMessage(nil), s.messages...)
}

// Refused returns the commands the server refused (plaintext MAIL, bad AUTH).
func (s *SMTPServer) Refused() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.refused...)
}

type smtpSession struct {
	s       *SMTPServer
	conn    net.Conn
	r       *bufio.Reader
	secured bool
	authed  string
	msg     *SMTPMessage
}

func (ss *smtpSession) reply(line string) { _, _ = ss.conn.Write([]byte(line + "\r\n")) }

func (ss *smtpSession) refuse(cmd, line string) {
	ss.s.mu.Lock()
	ss.s.refused = append(ss.s.refused, cmd)
	ss.s.mu.Unlock()
	ss.reply(line)
}

func (s *SMTPServer) session(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	ss := &smtpSession{s: s, conn: conn, r: bufio.NewReader(conn)}
	ss.reply("220 probectl-receipt ESMTP")
	for {
		line, err := ss.r.ReadString('\n')
		if err != nil {
			return
		}
		if !ss.handle(strings.TrimRight(line, "\r\n")) {
			return
		}
	}
}

// handle runs one command and reports whether the session continues.
func (ss *smtpSession) handle(cmd string) bool {
	upper := strings.ToUpper(cmd)
	switch {
	case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
		ss.reply("250-probectl-receipt")
		if !ss.secured {
			ss.reply("250-STARTTLS")
		} else if ss.s.user != "" {
			ss.reply("250-AUTH PLAIN")
		}
		ss.reply("250 8BITMIME")
	case upper == "STARTTLS":
		if ss.secured {
			ss.reply("454 already secured")
			return true
		}
		ss.reply("220 ready to start TLS")
		tc := tls.Server(ss.conn, ss.s.tlsCfg)
		if err := tc.Handshake(); err != nil {
			return false
		}
		ss.conn, ss.r, ss.secured = tc, bufio.NewReader(tc), true
	case strings.HasPrefix(upper, "AUTH PLAIN"):
		ss.auth(cmd)
	case strings.HasPrefix(upper, "MAIL FROM:"):
		switch {
		case !ss.secured:
			ss.refuse(cmd, "530 must issue STARTTLS first")
		case ss.s.user != "" && ss.authed == "":
			ss.refuse(cmd, "530 authentication required")
		default:
			ss.msg = &SMTPMessage{From: smtpAddr(cmd[len("MAIL FROM:"):]), User: ss.authed, TLS: ss.secured}
			ss.reply("250 sender ok")
		}
	case strings.HasPrefix(upper, "RCPT TO:"):
		if ss.msg == nil {
			ss.reply("503 need MAIL first")
			return true
		}
		ss.msg.To = append(ss.msg.To, smtpAddr(cmd[len("RCPT TO:"):]))
		ss.reply("250 recipient ok")
	case upper == "DATA":
		return ss.data()
	case upper == "RSET":
		ss.msg = nil
		ss.reply("250 reset")
	case upper == "QUIT":
		ss.reply("221 bye")
		return false
	default:
		ss.reply("250 ok")
	}
	return true
}

func (ss *smtpSession) auth(cmd string) {
	if !ss.secured {
		ss.refuse("AUTH PLAIN (plaintext session)", "530 must issue STARTTLS first")
		return
	}
	resp := strings.TrimSpace(cmd[len("AUTH PLAIN"):])
	if resp == "" {
		ss.reply("334 ")
		line, err := ss.r.ReadString('\n')
		if err != nil {
			return
		}
		resp = strings.TrimSpace(line)
	}
	raw, err := base64.StdEncoding.DecodeString(resp)
	parts := strings.Split(string(raw), "\x00")
	if err != nil || len(parts) != 3 || parts[1] != ss.s.user || parts[2] != ss.s.password {
		ss.refuse("AUTH PLAIN (bad credentials)", "535 authentication failed")
		return
	}
	ss.authed = parts[1]
	ss.reply("235 authenticated")
}

func (ss *smtpSession) data() bool {
	if ss.msg == nil || len(ss.msg.To) == 0 {
		ss.reply("503 need RCPT first")
		return true
	}
	ss.reply("354 end with <CRLF>.<CRLF>")
	var body strings.Builder
	for {
		line, err := ss.r.ReadString('\n')
		if err != nil {
			return false
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "." {
			break
		}
		body.WriteString(strings.TrimPrefix(trimmed, "."))
		body.WriteString("\n")
	}
	ss.msg.Data = body.String()
	ss.s.mu.Lock()
	ss.s.messages = append(ss.s.messages, *ss.msg)
	ss.s.mu.Unlock()
	ss.msg = nil
	ss.reply("250 queued")
	return true
}

// smtpAddr strips the angle brackets and parameters from a MAIL/RCPT path.
func smtpAddr(path string) string {
	path = strings.TrimSpace(path)
	if i := strings.IndexByte(path, '>'); i >= 0 {
		path = path[:i]
	}
	return strings.TrimPrefix(path, "<")
}
