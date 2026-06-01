package path

import "context"

// tracer runs single-flow traceroutes. The real ICMP/TCP engine implements it;
// tests use a fake. It is unexported so the public surface is just Run + the
// path model.
type tracer interface {
	resolve(target string) (string, error)
	traceFlow(ctx context.Context, cfg Config, targetIP string, flowID uint16) (flowTrace, error)
}

// discover runs cfg.TraceCount Paris traces with distinct flow identifiers (so an
// ECMP load-balancer keeps each on its own stable path, exploring the branches)
// and merges them into one multi-path Path.
func discover(ctx context.Context, tr tracer, cfg Config) (*Path, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	targetIP, err := tr.resolve(cfg.Target)
	if err != nil {
		return nil, err
	}
	traces := make([]flowTrace, 0, cfg.TraceCount)
	for i := 0; i < cfg.TraceCount; i++ {
		ft, err := tr.traceFlow(ctx, cfg, targetIP, flowIDFor(i))
		if err != nil {
			return nil, err
		}
		traces = append(traces, ft)
	}
	return mergeTraces(cfg, targetIP, traces), nil
}

// flowIDFor returns a distinct, non-zero flow identifier for the i-th trace.
func flowIDFor(i int) uint16 {
	return uint16(0xa001 + i*0x0111)
}
