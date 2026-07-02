// SPDX-License-Identifier: LicenseRef-probectl-TBD

package l7

import "time"

// Protocol identifiers (the on-the-wire value emitted as L7Call.protocol).
const (
	ProtoUnknown  = ""
	ProtoHTTP1    = "http1"
	ProtoHTTP2    = "http2"
	ProtoGRPC     = "grpc"
	ProtoDNS      = "dns"
	ProtoKafka    = "kafka"
	ProtoPostgres = "postgresql"
	ProtoMySQL    = "mysql"
)

// Kind labels a captured plaintext chunk's direction relative to the local app:
// Request bytes are what the app SENT, Response bytes are what it RECEIVED.
type Kind int

const (
	Request Kind = iota
	Response
)

// DataEvent is a plaintext chunk for one connection, as delivered by the capture
// layer (a TLS-uprobe read/write, or a socket read/write for cleartext).
type DataEvent struct {
	Kind    Kind
	Time    time.Time
	Payload []byte
	// Size is the chunk's TRUE plaintext size. Under a kernel capture window
	// (EBPF-002) Payload may carry fewer bytes than the application wrote —
	// len(Payload) is what was captured, Size is what happened. 0 = unknown
	// (fixture/cleartext sources), treat as len(Payload).
	Size int
}

// Call is one parsed application-protocol call: the unit the agent rolls up onto
// service edges and emits as an L7Call.
type Call struct {
	Protocol  string
	Method    string        // HTTP method | gRPC full-method | DNS qtype | Kafka API name | SQL operation
	Resource  string        // HTTP path | gRPC service/method | DNS qname | Kafka topic | redacted SQL
	Status    string        // HTTP status | grpc-status | DNS rcode | Kafka error code | SQL response
	Error     bool          // status denotes an error
	Start     time.Time     // when the request was observed
	Latency   time.Duration // request -> matching response
	ReqBytes  uint64
	RespBytes uint64
}

// Parser consumes a single connection's plaintext DataEvents in order and emits
// completed Calls. Flush returns any calls still buffered when the connection
// closes (e.g. a request with no observed response is dropped, not emitted).
type Parser interface {
	OnData(d DataEvent) []Call
	Flush() []Call
}
