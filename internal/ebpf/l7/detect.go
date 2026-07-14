// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package l7

import "bytes"

var http1Methods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
	[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "), []byte("TRACE "),
}

// http2Preface is the client connection preface that opens every HTTP/2 stream.
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// Detect guesses the application protocol from the first REQUEST bytes of a
// connection, with a destination-port hint (the agent knows the 5-tuple). gRPC
// is HTTP/2 with a grpc content-type, so it is resolved by the HTTP/2 parser,
// not here.
func Detect(reqHead []byte, dstPort uint32) string {
	if bytes.HasPrefix(reqHead, http2Preface) {
		return ProtoHTTP2
	}
	for _, m := range http1Methods {
		if bytes.HasPrefix(reqHead, m) {
			return ProtoHTTP1
		}
	}
	switch dstPort {
	case 53, 5353:
		return ProtoDNS
	case 3306:
		return ProtoMySQL
	case 5432:
		return ProtoPostgres
	case 9092, 9093:
		return ProtoKafka
	case 80, 8080:
		return ProtoHTTP1
	}
	return ProtoUnknown
}
