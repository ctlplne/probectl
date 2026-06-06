package canary

import (
	"math"
	"strings"
	"testing"
	"time"
)

// --- the MOS-model fixtures (the S47c 'Tests' line) ---

func TestMOSFromRFixtures(t *testing.T) {
	tests := []struct {
		r    float64
		want float64
		tol  float64
	}{
		{93.2, 4.41, 0.02}, // default-parameter R0 → the textbook ~4.41
		{80, 4.02, 0.02},   // "satisfied" band
		{70, 3.60, 0.02},   // "some users dissatisfied"
		{50, 2.58, 0.02},   // "nearly all dissatisfied"
		{0, 1, 0},          // floor
		{-20, 1, 0},        // clamped floor
		{100, 4.5, 0},      // ceiling
		{130, 4.5, 0},      // clamped ceiling
	}
	for _, tc := range tests {
		if got := mosFromR(tc.r); math.Abs(got-tc.want) > tc.tol {
			t.Errorf("mosFromR(%.1f) = %.3f want %.2f±%.2f", tc.r, got, tc.want, tc.tol)
		}
	}
}

func TestEModelFixtures(t *testing.T) {
	g711, g729 := voiceCodecs["g711"], voiceCodecs["g729"]

	// Clean short path (60ms one-way incl. codec+buffer), no loss: near-toll.
	r := eModelR(60, 0, g711)
	if mos := mosFromR(r); mos < 4.2 || mos > 4.45 {
		t.Errorf("clean g711 path: mos = %.2f want ~4.3-4.4 (r=%.1f)", mos, r)
	}

	// 20%% loss wrecks the call (G.107 loss curve): MOS deep into "poor".
	if mos := mosFromR(eModelR(60, 20, g711)); mos > 3.0 {
		t.Errorf("20%% loss g711: mos = %.2f want < 3.0", mos)
	}

	// The delay penalty kicks in past the 177.3ms knee.
	rShort, rLong := eModelR(100, 0, g711), eModelR(300, 0, g711)
	if rLong >= rShort {
		t.Errorf("delay must penalize: r(300ms)=%.1f >= r(100ms)=%.1f", rLong, rShort)
	}
	if d := rShort - rLong; d < 15 {
		t.Errorf("the 177.3ms knee term must bite: ΔR = %.1f want >= 15", d)
	}

	// g729's equipment impairment (Ie=11) lowers the ceiling vs g711.
	if rG729 := eModelR(60, 0, g729); rG729 >= eModelR(60, 0, g711) {
		t.Errorf("g729 must score below g711 on a clean path: %.1f", rG729)
	}
	// …but g729 degrades more slowly per loss point only relative to its
	// lower Bpl — at equal loss its ABSOLUTE R stays below g711's.
	if eModelR(60, 5, g729) >= eModelR(60, 5, g711) {
		t.Error("g729 must not outscore g711 at equal loss")
	}
}

func TestRFC3550Jitter(t *testing.T) {
	base := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	mk := func(offsetsMs ...float64) []time.Time {
		out := make([]time.Time, len(offsetsMs))
		for i, ms := range offsetsMs {
			out[i] = base.Add(time.Duration(ms * float64(time.Millisecond)))
		}
		return out
	}

	// Perfect cadence: send every 20ms, receive every 20ms → zero jitter.
	send := mk(0, 20, 40, 60)
	recv := mk(10, 30, 50, 70)
	if j := rfc3550JitterMs(send, recv); j != 0 {
		t.Errorf("constant transit must be zero jitter, got %.3f", j)
	}

	// One 8ms transit wobble → J = 8/16 = 0.5 after the first delta.
	recv = mk(10, 30, 58, 78)
	j := rfc3550JitterMs(send, recv)
	if j < 0.4 || j > 1.1 {
		t.Errorf("wobble jitter = %.3f want ~0.5-1.0", j)
	}

	// Losses are skipped, not counted as jitter.
	recvLossy := mk(10, 30, 50, 70)
	recvLossy[1] = time.Time{} // packet 1 lost
	if j := rfc3550JitterMs(send, recvLossy); j != 0 {
		t.Errorf("loss must not fabricate jitter, got %.3f", j)
	}
}

func TestJitterBufferModel(t *testing.T) {
	if jb := jitterBufferMs(1); jb != 40 {
		t.Errorf("floor: %.0f want 40", jb)
	}
	if jb := jitterBufferMs(35); jb != 70 {
		t.Errorf("2x rule: %.0f want 70", jb)
	}
	if jb := jitterBufferMs(200); jb != 120 {
		t.Errorf("cap: %.0f want 120", jb)
	}
}

// --- construction + config validation ---

func TestNewVoiceValidation(t *testing.T) {
	if _, err := NewVoice(Config{Type: voiceType, Target: "192.0.2.10:5004"}); err != nil {
		t.Fatalf("defaults must build: %v", err)
	}
	if _, err := NewVoice(Config{Type: voiceType, Target: "192.0.2.10"}); err == nil {
		t.Fatal("missing port must fail")
	}
	if _, err := NewVoice(Config{Type: voiceType, Target: "192.0.2.10:5004",
		Params: map[string]string{"codec": "opus"}}); err == nil || !strings.Contains(err.Error(), "unknown codec") {
		t.Fatal("unknown codec must fail with the allowlist")
	}
	if _, err := NewVoice(Config{Type: voiceType, Target: "192.0.2.10:5004",
		Params: map[string]string{"duration_seconds": "60"}}); err == nil {
		t.Fatal("out-of-range duration must fail")
	}
	c, err := NewVoice(Config{Type: voiceType, Target: "192.0.2.10:5004",
		Params: map[string]string{"codec": "G729", "duration_seconds": "2", "dscp": "46"}})
	if err != nil {
		t.Fatal(err)
	}
	if spec := c.Describe(); spec.Type != voiceType || !strings.Contains(spec.Description, "MOS") {
		t.Errorf("spec = %+v", spec)
	}
	vc := c.(*voiceCanary)
	if vc.codec.Name != "g729" || vc.seconds != 2 {
		t.Errorf("params not applied: %+v", vc)
	}
}

func TestVoiceCodecProfiles(t *testing.T) {
	g711 := voiceCodecs["g711"]
	if g711.PayloadType != 0 || g711.PayloadBytes != 160 || g711.FrameMs != 20 {
		t.Errorf("g711 profile wrong: %+v", g711)
	}
	g729 := voiceCodecs["g729"]
	if g729.PayloadType != 18 || g729.PayloadBytes != 20 {
		t.Errorf("g729 profile wrong: %+v", g729)
	}
}
