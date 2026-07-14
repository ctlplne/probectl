// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package l7

import (
	"encoding/binary"
	"strings"
	"time"
	"unicode"
)

type sqlReq struct {
	op    string
	query string
	start time.Time
	bytes uint64
}

type postgresParser struct {
	reqBuf, respBuf []byte
	pending         []sqlReq
}

func newPostgresParser() *postgresParser { return &postgresParser{} }

func (p *postgresParser) OnData(d DataEvent) []Call {
	if d.Kind == Request {
		if len(p.reqBuf)+len(d.Payload) > l7MaxBufBytes {
			p.reqBuf = p.reqBuf[:0]
			return nil
		}
		p.reqBuf = append(p.reqBuf, d.Payload...)
		for {
			msg, rest, ok := scanPostgresMessage(p.reqBuf)
			if !ok {
				break
			}
			p.reqBuf = rest
			if msg[0] != 'Q' || len(msg) < 6 {
				continue
			}
			query := stringTrimNUL(msg[5:])
			if query == "" {
				continue
			}
			p.addPending(sqlReq{op: sqlOperation(query), query: normalizeSQLQuery(query), start: d.Time, bytes: uint64(len(msg))})
		}
		return nil
	}

	if len(p.respBuf)+len(d.Payload) > l7MaxBufBytes {
		p.respBuf = p.respBuf[:0]
		return nil
	}
	p.respBuf = append(p.respBuf, d.Payload...)
	var calls []Call
	for {
		msg, rest, ok := scanPostgresMessage(p.respBuf)
		if !ok {
			break
		}
		p.respBuf = rest
		switch msg[0] {
		case 'C':
			if req, ok := p.popPending(); ok {
				status := stringTrimNUL(msg[5:])
				calls = append(calls, sqlCall(ProtoPostgres, req, status, false, d.Time, len(msg)))
			}
		case 'E':
			if req, ok := p.popPending(); ok {
				calls = append(calls, sqlCall(ProtoPostgres, req, "ERROR", true, d.Time, len(msg)))
			}
		}
	}
	return calls
}

func (p *postgresParser) Flush() []Call { return nil }

func (p *postgresParser) addPending(req sqlReq) {
	if len(p.pending) >= l7MaxPending {
		copy(p.pending, p.pending[1:])
		p.pending[len(p.pending)-1] = req
		return
	}
	p.pending = append(p.pending, req)
}

func (p *postgresParser) popPending() (sqlReq, bool) {
	if len(p.pending) == 0 {
		return sqlReq{}, false
	}
	req := p.pending[0]
	copy(p.pending, p.pending[1:])
	p.pending = p.pending[:len(p.pending)-1]
	return req, true
}

func scanPostgresMessage(buf []byte) (msg, rest []byte, ok bool) {
	if len(buf) < 5 {
		return nil, buf, false
	}
	size := int(binary.BigEndian.Uint32(buf[1:5]))
	total := 1 + size
	if size < 4 || total > l7MaxBufBytes || total > len(buf) {
		return nil, buf, false
	}
	return buf[:total], buf[total:], true
}

type mysqlParser struct {
	reqBuf, respBuf []byte
	pending         []sqlReq
}

func newMySQLParser() *mysqlParser { return &mysqlParser{} }

func (p *mysqlParser) OnData(d DataEvent) []Call {
	if d.Kind == Request {
		if len(p.reqBuf)+len(d.Payload) > l7MaxBufBytes {
			p.reqBuf = p.reqBuf[:0]
			return nil
		}
		p.reqBuf = append(p.reqBuf, d.Payload...)
		for {
			payload, frameLen, ok := scanMySQLPacket(p.reqBuf)
			if !ok {
				break
			}
			p.reqBuf = p.reqBuf[frameLen:]
			if len(payload) == 0 || payload[0] != 0x03 {
				continue
			}
			query := strings.TrimSpace(string(payload[1:]))
			if query == "" {
				continue
			}
			p.addPending(sqlReq{op: sqlOperation(query), query: normalizeSQLQuery(query), start: d.Time, bytes: uint64(frameLen)})
		}
		return nil
	}

	if len(p.respBuf)+len(d.Payload) > l7MaxBufBytes {
		p.respBuf = p.respBuf[:0]
		return nil
	}
	p.respBuf = append(p.respBuf, d.Payload...)
	var calls []Call
	for {
		payload, frameLen, ok := scanMySQLPacket(p.respBuf)
		if !ok {
			break
		}
		p.respBuf = p.respBuf[frameLen:]
		if len(payload) == 0 {
			continue
		}
		req, ok := p.popPending()
		if !ok {
			continue
		}
		status, isErr := "OK", false
		if payload[0] == 0xff {
			status, isErr = "ERR", true
			if len(payload) >= 3 {
				status = "ERR " + strconvItoa(int(binary.LittleEndian.Uint16(payload[1:3])))
			}
		}
		calls = append(calls, sqlCall(ProtoMySQL, req, status, isErr, d.Time, frameLen))
	}
	return calls
}

func (p *mysqlParser) Flush() []Call { return nil }

func (p *mysqlParser) addPending(req sqlReq) {
	if len(p.pending) >= l7MaxPending {
		copy(p.pending, p.pending[1:])
		p.pending[len(p.pending)-1] = req
		return
	}
	p.pending = append(p.pending, req)
}

func (p *mysqlParser) popPending() (sqlReq, bool) {
	if len(p.pending) == 0 {
		return sqlReq{}, false
	}
	req := p.pending[0]
	copy(p.pending, p.pending[1:])
	p.pending = p.pending[:len(p.pending)-1]
	return req, true
}

func scanMySQLPacket(buf []byte) (payload []byte, frameLen int, ok bool) {
	if len(buf) < 4 {
		return nil, 0, false
	}
	size := int(buf[0]) | int(buf[1])<<8 | int(buf[2])<<16
	total := 4 + size
	if size < 0 || total > l7MaxBufBytes || total > len(buf) {
		return nil, 0, false
	}
	return buf[4:total], total, true
}

func sqlCall(proto string, req sqlReq, status string, isErr bool, ts time.Time, respBytes int) Call {
	return Call{
		Protocol:  proto,
		Method:    req.op,
		Resource:  req.query,
		Status:    status,
		Error:     isErr,
		Start:     req.start,
		Latency:   ts.Sub(req.start),
		ReqBytes:  req.bytes,
		RespBytes: uint64(respBytes),
	}
}

func sqlOperation(query string) string {
	for _, field := range strings.Fields(query) {
		field = strings.Trim(field, "();")
		if field != "" && !strings.HasPrefix(field, "--") {
			return strings.ToUpper(field)
		}
	}
	return "QUERY"
}

func normalizeSQLQuery(query string) string {
	var b strings.Builder
	inSingle := false
	inDouble := false
	lastSpace := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
				if i+1 < len(query) && query[i+1] == '\'' {
					i++
					inSingle = true
				}
			}
			continue
		case inDouble:
			if c == '"' {
				inDouble = false
			}
			continue
		case c == '\'':
			b.WriteByte('?')
			inSingle = true
			lastSpace = false
		case c == '"':
			b.WriteByte('?')
			inDouble = true
			lastSpace = false
		case isSQLNumberStart(query, i):
			b.WriteByte('?')
			lastSpace = false
			for i+1 < len(query) && isSQLNumberContinue(query[i+1]) {
				i++
			}
		case unicode.IsSpace(rune(c)):
			if !lastSpace {
				b.WriteByte(' ')
				lastSpace = true
			}
		default:
			b.WriteByte(c)
			lastSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}

func isSQLNumberStart(s string, i int) bool {
	c := s[i]
	if c < '0' || c > '9' {
		return false
	}
	if i > 0 {
		prev := rune(s[i-1])
		if unicode.IsLetter(prev) || unicode.IsDigit(prev) || prev == '_' || prev == '.' {
			return false
		}
	}
	return true
}

func isSQLNumberContinue(c byte) bool {
	return (c >= '0' && c <= '9') || c == '.' || c == '_'
}

func stringTrimNUL(b []byte) string {
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
