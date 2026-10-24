// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"errors"
	"testing"
)

// D-43 S1: consented live capture never runs unfloored or unaudited. With no
// control-plane channel it is refused (requested, not active, the channel gauge
// says why); with a channel it starts only after the control plane recorded the
// posture it runs under, and a control plane that cannot record it defers the
// start to the next policy check.
func TestD43ConsentedCaptureRequiresTheChannel(t *testing.T) {
	rec := recordLiveStarts(t)
	a := d43Agent(t, consentedConfig(), nil)
	if len(rec.starts) != 0 || a.L7CaptureActive() || !a.L7CaptureRequested() || !a.L7CaptureChannelRefused() {
		t.Fatalf("no-channel capture: starts=%v active=%v requested=%v channel_refused=%v",
			rec.starts, a.L7CaptureActive(), a.L7CaptureRequested(), a.L7CaptureChannelRefused())
	}
}

func TestD43PostureIsRecordedBeforeCaptureStarts(t *testing.T) {
	rec := recordLiveStarts(t)
	cp := &fakeControlPlane{floor: "metadata", order: &rec.order}
	a := d43Agent(t, consentedConfig(), cp)
	if !a.L7CaptureActive() || len(rec.order) != 2 || rec.order[0] != "report:capturing" || rec.order[1] != "start" {
		t.Fatalf("order = %v, want the posture recorded before the start", rec.order)
	}
}

func TestD43UnrecordablePostureDefersCapture(t *testing.T) {
	rec := recordLiveStarts(t)
	cp := &fakeControlPlane{floor: "metadata", reportErr: errors.New("control plane down")}
	a := d43Agent(t, consentedConfig(), cp)
	if len(rec.starts) != 0 || a.L7CaptureActive() || !a.L7CaptureChannelRefused() {
		t.Fatalf("capture started without a recorded posture: %v", rec.starts)
	}
	if ev := a.retryDeferredL7(context.Background()); ev != nil {
		t.Fatal("retry attached while the control plane still cannot record")
	}
	cp.mu.Lock()
	cp.reportErr = nil
	cp.mu.Unlock()
	if ev := a.retryDeferredL7(context.Background()); ev == nil || !a.L7CaptureActive() || len(rec.starts) != 1 {
		t.Fatalf("retry did not attach once the posture was recorded: starts=%v", rec.starts)
	}
}

// The recorded fixture replay is not live capture: it needs no channel.
func TestD43FixtureReplayNeedsNoChannel(t *testing.T) {
	cfg := consentedConfig()
	cfg.L7CaptureEnabled, cfg.L7CaptureConsentTenant, cfg.L7CaptureScope = false, "", nil
	cfg.L7FixturePath = "testdata/l7.json"
	a := d43Agent(t, cfg, nil)
	if a.currentL7() == nil || a.L7CaptureChannelRefused() {
		t.Fatal("the fixture replay was refused for want of a channel")
	}
}
