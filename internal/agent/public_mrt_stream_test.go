// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

type publicImportClient struct {
	agentv1.AgentServiceClient
	check             func(context.Context, *agentv1.SubmitEntityEvidenceRequest) error
	resets, completed int
}

func (stub *publicImportClient) SubmitEntityEvidence(ctx context.Context, request *agentv1.SubmitEntityEvidenceRequest, _ ...grpc.CallOption) (*agentv1.SubmitEntityEvidenceResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if stub.check != nil {
		if err := stub.check(ctx, request); err != nil {
			return nil, err
		}
	}
	if table := request.PublicRoutingPeerTable; table != nil {
		state := "staged"
		if len(table.SourceRecord) < 20 {
			state = "invalidated"
		}
		return &agentv1.SubmitEntityEvidenceResponse{PublicRouting: &agentv1.PublicRoutingStagingReceipt{SnapshotId: table.ObservationId, Status: state}}, nil
	}
	message := request.PublicRoutingMessage
	state := "applied"
	if message.SourceReset {
		stub.resets++
		state = "invalidated"
	}
	if message.Complete {
		stub.completed++
	}
	return &agentv1.SubmitEntityEvidenceResponse{PublicRoutingMessage: &agentv1.PublicRoutingMessageReceipt{SnapshotId: message.SnapshotId, Sequence: message.Sequence, Status: state}}, nil
}

func importRecord(subtype uint16, body []byte) []byte {
	raw := binary.BigEndian.AppendUint32(nil, 1700000000)
	raw = binary.BigEndian.AppendUint16(raw, 13)
	raw = binary.BigEndian.AppendUint16(raw, subtype)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(body)))
	return append(raw, body...)
}

func importPeerTable() []byte { return importRecord(1, make([]byte, 8)) }

func importRIB() []byte {
	body := binary.BigEndian.AppendUint32(nil, ^uint32(0))
	body = append(body, 24, 192, 0, 2, 0, 0) // genuine zero-entry prefix
	return importRecord(2, body)
}

func importOptions() PublicMRTOptions {
	options := DefaultPublicMRTOptions("ris/mrt_table_dump_v2/rrc00")
	options.RetryDelay = time.Nanosecond
	return options
}

func TestPublicMRTImporterStreamsWholeInputAndKeepsExactAmbiguousRetries(t *testing.T) {
	const count = 5001
	peer, rib := importPeerTable(), importRIB()
	body := append(bytes.Clone(peer), bytes.Repeat(rib, count)...)
	reader := bytes.NewReader(body)
	var pending *agentv1.SubmitEntityEvidenceRequest
	var snapshot string
	var sequence int64 = 1
	seen, retry := 0, false
	stub := &publicImportClient{check: func(_ context.Context, request *agentv1.SubmitEntityEvidenceRequest) error {
		if request.PublicRoutingPeerTable != nil {
			if reader.Len() != len(body)-len(peer) || !bytes.Equal(request.PublicRoutingPeerTable.SourceRecord, peer) {
				t.Fatal("public MRT importer buffered the file or changed its original peer table")
			}
			snapshot = request.PublicRoutingPeerTable.ObservationId
			return nil
		}
		message := request.PublicRoutingMessage
		if message.SnapshotId != snapshot || message.Sequence != sequence || message.ObservedUnixNanos <= 0 || message.SourceReset {
			t.Fatal("public MRT importer changed source scope or sequence", message)
		}
		if pending != nil {
			if !proto.Equal(pending, request) {
				t.Fatal("public MRT ambiguous retry changed original bytes, capture clock or sequence")
			}
			pending = nil
		} else if seen == 0 && !retry {
			pending, retry = proto.Clone(request).(*agentv1.SubmitEntityEvidenceRequest), true
			return status.Error(codes.Unavailable, "lost acknowledgement")
		}
		if message.Complete {
			if reader.Len() != 0 || seen != count || len(message.Record) != 0 {
				t.Fatal("public MRT importer published before complete original EOF")
			}
		} else {
			seen++
			if !bytes.Equal(message.Record, rib) || reader.Len() != len(body)-len(peer)-seen*len(rib) {
				t.Fatal("public MRT importer truncated or buffered original records")
			}
			sequence++
		}
		return nil
	}}
	options := importOptions()
	options.RecordBytes = 128 // per-record admission cannot become a file cap
	got, err := (&EvidenceClient{svc: stub}).ImportPublicMRT(t.Context(), reader, options)
	if err != nil || got.SnapshotID != snapshot || got.Records != count+1 || got.Bytes != int64(len(body)) || seen != count || stub.completed != 1 || stub.resets != 0 || !retry {
		t.Fatal("public MRT importer lost whole source or exact retry", got, err, seen, stub.completed, stub.resets)
	}
}

func TestPublicMRTImporterRefusesPartialReplacedUnadmittedAndCanceledSources(t *testing.T) {
	for _, scenario := range []string{"partial-header", "partial-body", "replaced-table", "unknown-record", "over-budget", "canceled", "rpc-refusal"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			peer, rib := importPeerTable(), importRIB()
			last := bytes.Clone(rib)
			options := importOptions()
			switch scenario {
			case "partial-header":
				last = last[:3]
			case "partial-body":
				last = last[:len(last)-1]
			case "replaced-table":
				last = peer
			case "unknown-record":
				last[5] = 16
			case "over-budget":
				binary.BigEndian.PutUint32(last[8:12], 1<<30)
			}
			stub := &publicImportClient{check: func(call context.Context, request *agentv1.SubmitEntityEvidenceRequest) error {
				message := request.PublicRoutingMessage
				if message == nil || message.SourceReset {
					if call.Err() != nil {
						t.Fatal("public MRT source reset reused canceled import context")
					}
					return nil
				}
				if scenario == "canceled" {
					cancel()
				}
				if scenario == "rpc-refusal" {
					return status.Error(codes.PermissionDenied, "current source revoked")
				}
				return nil
			}}
			body := append(append(bytes.Clone(peer), rib...), last...)
			if got, err := (&EvidenceClient{svc: stub}).ImportPublicMRT(ctx, bytes.NewReader(body), options); err == nil || got.SnapshotID == "" || stub.completed != 0 || stub.resets != 1 {
				t.Fatal("public MRT importer published partial or refused source without reset", got, err, stub.completed, stub.resets)
			}
		})
	}
}

func TestPublicMRTFileCompressionRequiresCleanWholeEOF(t *testing.T) {
	peer := importPeerTable()
	var zipped bytes.Buffer
	writer := gzip.NewWriter(&zipped)
	if _, err := writer.Write(peer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	// One exact original empty-peer MRT record, compressed with bzip2.
	bzip, err := base64.StdEncoding.DecodeString("QlpoOTFBWSZTWWmylmEAAAfDAORCCAACACAAIAAiMQeoQwItx0bEjjxdyRThQkGmylmE")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		raw    []byte
		refuse bool
	}{
		{"plain", peer, false}, {"gzip", zipped.Bytes(), false}, {"bzip2", bzip, false},
		{"gzip-truncated", zipped.Bytes()[:zipped.Len()-1], true},
		{"gzip-trailing-garbage", append(bytes.Clone(zipped.Bytes()), 255), true},
		{"bzip2-truncated", bzip[:len(bzip)-1], true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "original.input") // extension proves nothing
			if err := os.WriteFile(file, tc.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := OpenPublicMRTFile(file)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = source.Close() })
			stub := &publicImportClient{}
			_, err = (&EvidenceClient{svc: stub}).ImportPublicMRT(t.Context(), source, importOptions())
			if tc.refuse {
				if err == nil || stub.completed != 0 || stub.resets != 1 {
					t.Fatal("compressed public MRT corruption became a complete EOF", err, stub.completed, stub.resets)
				}
			} else if err != nil || stub.completed != 1 || stub.resets != 0 {
				t.Fatal("complete compressed original MRT file was refused", err, stub.completed, stub.resets)
			}
		})
	}
	if _, err := OpenPublicMRTFile(t.TempDir()); err == nil {
		t.Fatal("public MRT accepted a non-regular source")
	}
}

func TestPublicMRTImporterReportsFailedRetirementAndRefusesEmptyFirstRecord(t *testing.T) {
	retirement := errors.New("source retirement unavailable")
	stub := &publicImportClient{check: func(_ context.Context, request *agentv1.SubmitEntityEvidenceRequest) error {
		if request.GetPublicRoutingMessage().GetSourceReset() {
			return retirement
		}
		return nil
	}}
	body := append(importPeerTable(), 1)
	if _, err := (&EvidenceClient{svc: stub}).ImportPublicMRT(t.Context(), bytes.NewReader(body), importOptions()); !errors.Is(err, retirement) || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal("public MRT importer hid an unacknowledged source retirement", err)
	}
	stub = &publicImportClient{}
	if _, err := (&EvidenceClient{svc: stub}).ImportPublicMRT(t.Context(), bytes.NewReader(nil), importOptions()); err == nil || stub.completed != 0 {
		t.Fatal("empty original MRT input fabricated a complete empty source", err)
	}
}
