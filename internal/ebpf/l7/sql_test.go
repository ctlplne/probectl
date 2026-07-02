// SPDX-License-Identifier: LicenseRef-probectl-TBD

package l7

import (
	"encoding/binary"
	"testing"
	"time"
)

func postgresMsg(kind byte, payload []byte) []byte {
	out := make([]byte, 5+len(payload))
	out[0] = kind
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(payload)))
	copy(out[5:], payload)
	return out
}

func mysqlPacket(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = byte(len(payload))
	out[1] = byte(len(payload) >> 8)
	out[2] = byte(len(payload) >> 16)
	copy(out[4:], payload)
	return out
}

func TestPostgresSimpleQueryStatusLatencyAndRedaction(t *testing.T) {
	p := newPostgresParser()
	t0 := time.Unix(100, 0)
	req := postgresMsg('Q', []byte("SELECT * FROM users WHERE email = 'a@example.com' AND id = 42\x00"))
	resp := postgresMsg('C', []byte("SELECT 1\x00"))

	if calls := p.OnData(DataEvent{Kind: Request, Time: t0, Payload: req}); len(calls) != 0 {
		t.Fatalf("request emitted %d calls, want 0", len(calls))
	}
	calls := p.OnData(DataEvent{Kind: Response, Time: t0.Add(9 * time.Millisecond), Payload: resp})
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.Protocol != ProtoPostgres || c.Method != "SELECT" || c.Status != "SELECT 1" || c.Error {
		t.Errorf("call = %+v", c)
	}
	if c.Resource != "SELECT * FROM users WHERE email = ? AND id = ?" {
		t.Errorf("resource = %q", c.Resource)
	}
	if c.Latency != 9*time.Millisecond {
		t.Errorf("latency = %v, want 9ms", c.Latency)
	}
}

func TestPostgresErrorResponse(t *testing.T) {
	p := newPostgresParser()
	t0 := time.Unix(1, 0)
	p.OnData(DataEvent{Kind: Request, Time: t0, Payload: postgresMsg('Q', []byte("UPDATE accounts SET token = 'secret'\x00"))})
	calls := p.OnData(DataEvent{Kind: Response, Time: t0.Add(time.Millisecond), Payload: postgresMsg('E', []byte("SERROR\x00"))})
	if len(calls) != 1 || calls[0].Status != "ERROR" || !calls[0].Error {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].Resource != "UPDATE accounts SET token = ?" {
		t.Errorf("resource = %q", calls[0].Resource)
	}
}

func TestMySQLComQueryStatusLatencyAndRedaction(t *testing.T) {
	p := newMySQLParser()
	t0 := time.Unix(200, 0)
	query := append([]byte{0x03}, []byte("insert into orders values (123, 'card-4111')")...)
	if calls := p.OnData(DataEvent{Kind: Request, Time: t0, Payload: mysqlPacket(query)}); len(calls) != 0 {
		t.Fatalf("request emitted %d calls, want 0", len(calls))
	}
	calls := p.OnData(DataEvent{Kind: Response, Time: t0.Add(3 * time.Millisecond), Payload: mysqlPacket([]byte{0x00})})
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.Protocol != ProtoMySQL || c.Method != "INSERT" || c.Status != "OK" || c.Error {
		t.Errorf("call = %+v", c)
	}
	if c.Resource != "insert into orders values (?, ?)" {
		t.Errorf("resource = %q", c.Resource)
	}
}

func TestMySQLErrorResponse(t *testing.T) {
	p := newMySQLParser()
	t0 := time.Unix(3, 0)
	p.OnData(DataEvent{Kind: Request, Time: t0, Payload: mysqlPacket(append([]byte{0x03}, []byte("delete from users where id=9")...))})
	calls := p.OnData(DataEvent{Kind: Response, Time: t0.Add(time.Millisecond), Payload: mysqlPacket([]byte{0xff, 0x48, 0x04})})
	if len(calls) != 1 || calls[0].Status != "ERR 1096" || !calls[0].Error {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestTrackerDetectsSQLByPort(t *testing.T) {
	m := NewManager()
	t0 := time.Unix(4, 0)
	m.OnData(1, 5432, DataEvent{Kind: Request, Time: t0, Payload: postgresMsg('Q', []byte("select 1\x00"))})
	pg := m.OnData(1, 5432, DataEvent{Kind: Response, Time: t0.Add(time.Millisecond), Payload: postgresMsg('C', []byte("SELECT 1\x00"))})
	if len(pg) != 1 || pg[0].Protocol != ProtoPostgres {
		t.Fatalf("postgres calls = %+v", pg)
	}

	m.OnData(2, 3306, DataEvent{Kind: Request, Time: t0, Payload: mysqlPacket(append([]byte{0x03}, []byte("select 1")...))})
	my := m.OnData(2, 3306, DataEvent{Kind: Response, Time: t0.Add(time.Millisecond), Payload: mysqlPacket([]byte{0x00})})
	if len(my) != 1 || my[0].Protocol != ProtoMySQL {
		t.Fatalf("mysql calls = %+v", my)
	}
}

func TestDetectSQLPorts(t *testing.T) {
	if got := Detect(nil, 5432); got != ProtoPostgres {
		t.Fatalf("postgres detect = %q", got)
	}
	if got := Detect(nil, 3306); got != ProtoMySQL {
		t.Fatalf("mysql detect = %q", got)
	}
}
