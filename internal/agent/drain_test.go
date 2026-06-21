// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
)

func TestDrainOnceSendsOnlyConfiguredChunk(t *testing.T) {
	buf := fillDrainBuffer(t, 10_000)
	a := &Agent{
		cfg: &Config{Buffer: BufferConfig{
			DrainMaxRecords: 500,
			DrainMaxBytes:   64 << 20,
			DrainPace:       Duration(time.Nanosecond),
		}},
		buffer: buf,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	client := &fakeDrainClient{}

	if err := a.drainOnce(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if len(client.streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(client.streams))
	}
	if got := len(client.streams[0].sent); got != 500 {
		t.Fatalf("stream sent %d requests, want configured chunk 500", got)
	}
	if got := buf.Len(); got != 9500 {
		t.Fatalf("buffer len after one chunk = %d, want 9500", got)
	}
}

func TestDrainOnceRemovesOnlyAckedPrefix(t *testing.T) {
	buf := fillDrainBuffer(t, 50)
	a := &Agent{
		cfg: &Config{Buffer: BufferConfig{
			DrainMaxRecords: 50,
			DrainMaxBytes:   64 << 20,
			DrainPace:       Duration(time.Nanosecond),
		}},
		buffer: buf,
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	accepted := uint64(10)
	client := &fakeDrainClient{accepted: &accepted}

	if err := a.drainOnce(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if got := len(client.streams[0].sent); got != 50 {
		t.Fatalf("stream sent %d requests, want 50", got)
	}
	if got := buf.Len(); got != 40 {
		t.Fatalf("buffer len after partial ack = %d, want 40", got)
	}
}

func BenchmarkDrainOnceReconnectStorm(b *testing.B) {
	frames := make([][]byte, 10_000)
	for i := range frames {
		frames[i] = mustMarshalResultEnvelope(b, testResultEnvelope("tenant-storm", "agent-storm", "storm-result"))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		buf, err := OpenBufferWithBytes(b.TempDir(), len(frames), -1)
		if err != nil {
			b.Fatal(err)
		}
		buf.fsync = false
		for _, frame := range frames {
			if err := buf.Enqueue(frame); err != nil {
				b.Fatal(err)
			}
		}
		a := &Agent{
			cfg: &Config{Buffer: BufferConfig{
				DrainMaxRecords: 500,
				DrainMaxBytes:   8 << 20,
				DrainPace:       Duration(time.Nanosecond),
			}},
			buffer: buf,
			log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		client := &fakeDrainClient{}
		b.StartTimer()
		if err := a.drainOnce(context.Background(), client); err != nil {
			b.Fatal(err)
		}
		if sent := len(client.streams[0].sent); sent > 500 {
			b.Fatalf("drain chunk sent %d requests, want <= 500", sent)
		}
	}
}

func fillDrainBuffer(tb testing.TB, records int) *Buffer {
	tb.Helper()
	buf, err := OpenBufferWithBytes(tb.TempDir(), records, -1)
	if err != nil {
		tb.Fatal(err)
	}
	buf.fsync = false
	for i := 0; i < records; i++ {
		frame := mustMarshalResultEnvelope(tb, testResultEnvelope("tenant-drain", "agent-drain", "result-drain"))
		if err := buf.Enqueue(frame); err != nil {
			tb.Fatal(err)
		}
	}
	return buf
}

type fakeDrainClient struct {
	streams  []*fakeResultStream
	accepted *uint64
}

func (c *fakeDrainClient) StreamResults(context.Context) (resultStream, error) {
	stream := &fakeResultStream{accepted: c.accepted}
	c.streams = append(c.streams, stream)
	return stream, nil
}

type fakeResultStream struct {
	sent     []*agentv1.StreamResultsRequest
	accepted *uint64
}

func (s *fakeResultStream) Send(req *agentv1.StreamResultsRequest) error {
	s.sent = append(s.sent, req)
	return nil
}

func (s *fakeResultStream) CloseAndRecv() (*agentv1.StreamResultsResponse, error) {
	if s.accepted != nil {
		return &agentv1.StreamResultsResponse{Accepted: *s.accepted}, nil
	}
	return &agentv1.StreamResultsResponse{Accepted: uint64(len(s.sent))}, nil
}
