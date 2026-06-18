// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/bus"
)

type captureBus struct {
	topic string
	group string
}

func (b *captureBus) Publish(context.Context, string, []byte, []byte) error { return nil }
func (b *captureBus) Subscribe(_ context.Context, topic, group string, _ bus.Handler) error {
	b.topic = topic
	b.group = group
	return nil
}
func (b *captureBus) Close() error { return nil }

func TestResultFanUsesPerReplicaViewGroup(t *testing.T) {
	SetInstanceGroupSuffix("pod-a")
	t.Cleanup(func() { SetInstanceGroupSuffix("") })

	b := &captureBus{}
	if err := NewResultFan(b, nil).WithViewGroup("result-read-views").Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.topic != bus.NetworkResultsTopic {
		t.Fatalf("topic = %q, want %q", b.topic, bus.NetworkResultsTopic)
	}
	if b.group != "result-read-views-pod-a" {
		t.Fatalf("group = %q, want per-replica result-read-views-pod-a", b.group)
	}
}

func TestResultFanDefaultGroupStaysShared(t *testing.T) {
	SetInstanceGroupSuffix("pod-a")
	t.Cleanup(func() { SetInstanceGroupSuffix("") })

	b := &captureBus{}
	if err := NewResultFan(b, nil).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.group != "result-fan" {
		t.Fatalf("group = %q, want shared result-fan", b.group)
	}
}
