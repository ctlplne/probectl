# Voice / RTP tests

## What it is

The **`voice` canary** answers one question: *if you placed a phone call across
this path right now, how good would it sound?* It does that not by guessing from
ping times, but by sending **real RTP packets** (RTP — the Real-time Transport
Protocol — is what virtually all VoIP audio rides in) — the same
packet format and
timing a softphone uses — to a target that echoes them back, then scoring the
echoes the way a phone's own quality meter would. The probe is a stunt double
for a call: dressed exactly like one (packet size, 20 ms cadence, QoS
marking), so the network treats it like one — but nobody is talking.

From those echoes it computes three numbers operators recognize:

- **MOS** (Mean Opinion Score, 1.0–4.5) — the headline "call quality" score,
  derived from the ITU-T G.107 **E-model** (the standard formula for
  predicting how listeners would rate a call from measurable impairments —
  delay, loss, codec) by mapping its **R-factor**, a 0–100
  transmission-quality rating, onto the familiar opinion scale.
- **Jitter** — how unevenly packets arrived (RFC 3550 interarrival estimator).
- **Packet loss** — how many of the RTP packets never came back.

It is a standard canary like ICMP or HTTP: you create a test, it runs on a
schedule, and the result flows through the normal pipeline (the
agent-to-first-result journey is [`getting-started.md`](getting-started.md)).
The implementation lives in `internal/canary/voice.go`.

## Creating a test

```json
POST /v1/tests
{"name": "voip to pbx", "type": "voice", "target": "pbx.acme.example:5004",
 "interval_seconds": 60, "timeout_seconds": 3,
 "params": {"codec": "g711", "duration_seconds": "3", "dscp": "46"}}
```

| Param | Default | Meaning |
|---|---|---|
| `codec` | `g711` | codec preset: `g711` (PCMU, 50 packets/s, 160 B payload) or `g729` (50 packets/s, 20 B payload) |
| `duration_seconds` | `3` | simulated call length (1–10 s; the codec sends 50 packets/s) |
| `dscp` | `46` | DSCP marking (EF = 46 by convention for voice) |

A **codec** is the voice encoder: G.711 is the uncompressed classic (bigger
packets, robust to loss; PCMU is its μ-law variant), G.729 the compressed one
(smaller packets, more sensitive to loss). **DSCP** (Differentiated Services
Code Point) is the priority tag in the IP header; **EF** (Expedited
Forwarding, value 46) is the class real voice conventionally rides.

The target must **echo the UDP datagrams** back — that can be a probectl agent
acting as a responder, or any plain UDP echo service. A target that does *not*
echo shows up as **100% loss** and an explicit *"voice path unmeasurable"*
failure. It never invents a score from a silent target.

## How it works — sending a call and listening to the echo

The canary opens a UDP connection and, for the configured duration, streams
RTP-framed packets at the codec's cadence:

1. **Frame and send.** Each packet carries a real RTP header (version 2, the
   codec's payload type — its registered RTP number — a per-packet sequence
   number, and an 8 kHz timestamp, the narrowband audio clock)
   followed by a payload of the codec's size. For G.711 that's a 12-byte header +
   160-byte payload every 20 ms — exactly 50 packets per second.
2. **Match the echoes.** A reader goroutine receives the reflected packets and
   matches each one to the packet it sent, keyed by the stream's SSRC (the
   random stream ID stamped in every RTP header) and the RTP
   sequence number. The send time and the receive time of every matched packet
   are recorded.
3. **Score from the round-trips.** From those send/receive pairs the canary
   derives per-packet RTT, loss, and jitter, then runs the E-model to turn delay
   + loss + codec into an R-factor and finally a MOS.

The DSCP marking is applied to the outgoing socket so the packets traverse the
network in the same QoS class real voice would — testing the path voice actually
takes, not a best-effort one.

## The model (and its honesty)

A MOS number looks authoritative, and the biggest risk with voice scoring is
that people over-trust it. So probectl uses a **deliberately simplified,
transport-only E-model** and **says so on every result**
(`voice.model = itu-t-g107-e-model-simplified`). Here's the actual math the code
runs, and what each piece assumes:

- **The rating** `R = 93.2 − Id − Ie,eff`. The `93.2` is the default-parameter R0
  (no advantage factor, no simultaneous-impairment terms — the conservative
  baseline).
- **Delay impairment** `Id = 0.024·d + 0.11·(d − 177.3)·H(d − 177.3)` — the G.107
  delay curve, with its characteristic 177.3 ms "knee" past which delay hurts much
  more: the satellite-call threshold, below which delay is barely felt and past
  which people start talking over each other. The one-way delay `d` is
  **estimated** (you can't measure one-way delay
  from an echo) as `RTT/2 + codec delay + a modeled jitter buffer` — and the
  result discloses that estimate (`voice.one_way_estimate`). The **jitter
  buffer** — the small reservoir a real phone uses to smooth uneven packet
  arrival into steady audio, at the price of added delay — is
  modeled as twice the measured jitter, floored at 40 ms and capped at 120 ms,
  matching what a real endpoint would add.
- **Loss impairment** `Ie,eff = Ie + (95 − Ie)·Ppl/(Ppl + Bpl)` — using the G.113
  codec parameters (`g711`: Ie 0, Bpl 25.1; `g729`: Ie 11, Bpl 19) under a
  random-loss assumption (losses spread out, not bursty — bursty loss degrades
  real calls more than this formula credits).
- **MOS** is mapped from R via the G.107 Annex-B cubic, clamped to a 1.0 floor and
  a 4.5 ceiling.
- **Jitter** is the RFC 3550 §6.4.1 interarrival estimator over the received
  packets (`J += (|D| − J)/16`), reported as `voice.jitter.ms`.

**Narrowband codecs only.** That `93.2` baseline *is* the narrowband model.
Wideband / HD-voice codecs (G.722, Opus) need the wideband E-model variant, which
is a different calculation — so it's marked out of scope and documented rather
than approximated with the wrong formula.

## Result fields (the contract)

**Metrics:** `voice.mos`, `voice.r_factor`, `voice.jitter.ms`, `voice.one_way.ms`,
`voice.loss.pct`, plus the standard latency family
(`rtt.min/avg/max/stddev.ms`, `loss.ratio`, `packets.sent/received`).

**Attributes:** `voice.codec`, `voice.model`, `voice.method`
(`rtp-udp-echo-reflection`), `voice.jitter_buffer_ms`, `voice.one_way_estimate`.

Results render in the result-detail view (reached from the Targets & Tests
pages) with MOS up front (≥4.0 good / ≥3.6 fair / below = poor) and the model
named alongside it — so a *computed* score is never presented as a *measured*
listening test.

## What it deliberately does not do

- **No SIP / call control.** There's no signaling — this measures RTP transport
  quality only. It does not register, dial, or tear down a call.
- **No wideband codecs** (see the narrowband note above).
- **No reflector infrastructure to own.** Agent-to-agent reflection reuses the
  existing a2a responder (a2a — agent-to-agent: one probectl agent echoing
  another's probes) rather than standing up a separate echo fleet.
