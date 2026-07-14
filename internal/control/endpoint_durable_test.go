// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store/endpointstore"
)

type endpointTestBinding map[[2]string]bool

func (b endpointTestBinding) Verify(_ context.Context, tenant, agent string) error {
	if b[[2]string{tenant, agent}] {
		return nil
	}
	return pipeline.ErrTenantNotBound
}

type endpointCaptureBus struct {
	published []bus.Message
	fail      error
}

func (b *endpointCaptureBus) Publish(_ context.Context, topic string, key, value []byte) error {
	if b.fail != nil {
		return b.fail
	}
	b.published = append(b.published, bus.Message{Topic: topic, Key: key, Value: value})
	return nil
}
func (*endpointCaptureBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (*endpointCaptureBus) Close() error                                                 { return nil }

type failingEndpointStore struct{ endpointstore.Store }

func (failingEndpointStore) Insert(context.Context, []endpointstore.Event) error {
	return errors.New("clickhouse unavailable")
}

func TestEndpointDurableConsumerIsolation(t *testing.T) {
	ctx := context.Background()
	durable := endpointstore.NewMemory()
	repo := endpoint.NewRepository(durable, endpoint.NewSnapshotStore(0))
	consumer := NewEndpointEventConsumer(&endpointCaptureBus{}, repo, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithTenantBinding(endpointTestBinding{{"tenant-a", "agent-a"}: true})

	message := func(tenant string) bus.Message {
		value, err := proto.Marshal(&resultv1.Result{
			TenantId: tenant, AgentId: "agent-a", CanaryType: endpoint.TypeWiFi,
			ServerAddress: tenant + "-ssid", Success: true, StartTimeUnixNano: time.Now().UnixNano(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return bus.Message{Topic: bus.EndpointResultsTopic, Key: []byte(tenant), Value: value}
	}

	// Agent A is registered only to tenant A: a payload claiming B must reach
	// neither tenant partition.
	if err := consumer.handleLane(ctx, message("tenant-b"), ""); err != nil {
		t.Fatal(err)
	}
	if rows, _ := durable.Latest(ctx, "tenant-b"); len(rows) != 0 {
		t.Fatalf("forged tenant persisted: %+v", rows)
	}
	if err := consumer.handleLane(ctx, message("tenant-a"), ""); err != nil {
		t.Fatal(err)
	}
	rows, err := durable.Latest(ctx, "tenant-a")
	if err != nil || len(rows) != 1 || rows[0].AgentID != "agent-a" {
		t.Fatalf("authoritative tenant write rows=%+v err=%v", rows, err)
	}
}

func TestEndpointDurableConsumerPreservesDLQ(t *testing.T) {
	ctx := context.Background()
	deadletters := &endpointCaptureBus{}
	repo := endpoint.NewRepository(failingEndpointStore{Store: endpointstore.NewMemory()}, endpoint.NewSnapshotStore(0))
	consumer := NewEndpointEventConsumer(deadletters, repo, nil)
	consumer.retries = 0
	value, _ := proto.Marshal(&resultv1.Result{
		TenantId: "tenant-a", AgentId: "agent-a", CanaryType: endpoint.TypeWiFi,
		StartTimeUnixNano: time.Now().UnixNano(),
	})
	msg := bus.Message{Topic: bus.EndpointResultsTopic, Key: []byte("tenant-a"), Value: value}
	if err := consumer.handleLane(ctx, msg, ""); err != nil {
		t.Fatalf("durable failure with working DLQ should be safely handled: %v", err)
	}
	if len(deadletters.published) != 1 || deadletters.published[0].Topic != bus.DeadLetterResultsTopic ||
		string(deadletters.published[0].Value) != string(value) {
		t.Fatalf("original endpoint protobuf not dead-lettered: %+v", deadletters.published)
	}
	deadletters.fail = errors.New("broker down")
	if err := consumer.handleLane(ctx, msg, ""); err == nil {
		t.Fatal("store + DLQ failure must leave the source offset uncommitted")
	}
}
