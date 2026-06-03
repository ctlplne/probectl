package control

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/netctl/internal/bus"
	"github.com/imfeelingtheagi/netctl/internal/config"
	resultv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/result/v1"
	"github.com/imfeelingtheagi/netctl/internal/incident"
	"github.com/imfeelingtheagi/netctl/internal/siem"
	"github.com/imfeelingtheagi/netctl/internal/threat"
)

// BuildTLSAnalyzer builds the S27 TLS/cert posture analyzer from config. CT
// correlation is enabled only when the operator opts in (external fetch — AUP /
// sovereignty / no-phone-home).
func BuildTLSAnalyzer(cfg *config.Config) *threat.Analyzer {
	var ct threat.CTChecker
	if cfg.CTEnabled {
		ct = threat.NewCrtSh(cfg.CTEndpoint, 10*time.Second)
	}
	return threat.NewAnalyzer(threat.Config{
		ExpiryWarning: cfg.TLSExpiryWarning,
		CertctlURL:    cfg.CertctlURL,
	}, ct)
}

// TLSPostureConsumer subscribes to the network-results topic and, for HTTPS
// synthetic results, analyzes the ALREADY-CAPTURED TLS data (S13) into TLS/cert
// posture findings — correlating each into a threat-plane incident (feeding the
// unified timeline + alerting, S16/S17). It NEVER re-handshakes (S27 watch-out).
type TLSPostureConsumer struct {
	bus        bus.Bus
	correlator *incident.Correlator
	analyzer   *threat.Analyzer
	siem       *siem.Forwarder
	log        *slog.Logger
}

// NewTLSPostureConsumer builds the consumer.
func NewTLSPostureConsumer(b bus.Bus, c *incident.Correlator, a *threat.Analyzer, log *slog.Logger) *TLSPostureConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &TLSPostureConsumer{bus: b, correlator: c, analyzer: a, log: log}
}

// WithSIEM forwards each TLS/cert posture signal to the SIEM (S32) in addition to
// correlating it into an incident. nil disables it (the default).
func (cs *TLSPostureConsumer) WithSIEM(fw *siem.Forwarder) *TLSPostureConsumer {
	cs.siem = fw
	return cs
}

// Run subscribes until ctx is canceled.
func (cs *TLSPostureConsumer) Run(ctx context.Context) error {
	return cs.bus.Subscribe(ctx, bus.NetworkResultsTopic, "tls-posture",
		func(ctx context.Context, msg bus.Message) error {
			var r resultv1.Result
			if err := proto.Unmarshal(msg.Value, &r); err != nil {
				cs.log.Warn("skipping malformed result", "error", err)
				return nil
			}
			for _, sig := range cs.signals(ctx, &r) {
				if _, err := cs.correlator.Ingest(ctx, sig); err != nil {
					cs.log.Warn("correlate tls posture into incident failed", "error", err)
				}
				if cs.siem != nil {
					if err := cs.siem.Enqueue(ctx, signalToSIEM(sig)); err != nil {
						cs.log.Warn("forward tls posture to siem failed", "error", err)
					}
				}
			}
			return nil
		})
}

// signals analyzes one result's captured TLS into threat-plane signals — nil for
// a non-HTTPS result or a clean posture.
func (cs *TLSPostureConsumer) signals(ctx context.Context, r *resultv1.Result) []incident.Signal {
	if r.GetCanaryType() != "http" {
		return nil
	}
	obs, ok := threat.FromCanaryAttributes(r.GetServerAddress(), r.GetAttributes(), time.Unix(0, r.GetStartTimeUnixNano()))
	if !ok {
		return nil
	}
	return threat.ToSignals(r.GetTenantId(), cs.analyzer.Analyze(ctx, obs))
}
