package canary

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

const tcpType = "tcp"

// tcpCanary measures TCP connect latency and reachability (a connect-based,
// unprivileged equivalent of a TCP-SYN test): it establishes a connection and
// records the time to complete the handshake.
type tcpCanary struct {
	guard   *TargetGuard
	host    string
	port    string
	count   int
	dscp    int
	timeout time.Duration // per-connect timeout
	spacing time.Duration
}

// NewTCP builds a TCP connect canary. The target is host:port, or a host with
// the port in Params["port"]. Params: count, dscp (0-63).
func NewTCP(cfg Config) (Canary, error) {
	host, port, err := splitTarget(cfg.Target, cfg.Params["port"])
	if err != nil {
		return nil, fmt.Errorf("tcp: %w", err)
	}
	c := &tcpCanary{host: host, port: port, count: 3, timeout: cfg.Timeout, guard: GuardFromParams(cfg.Params)}
	if err := c.guard.CheckHost(host); err != nil {
		return nil, fmt.Errorf("tcp: %w", err)
	}
	if c.timeout <= 0 {
		c.timeout = 3 * time.Second
	}
	if err := intParam(cfg.Params, "count", &c.count, 1, 100000); err != nil {
		return nil, err
	}
	if err := intParam(cfg.Params, "dscp", &c.dscp, 0, 63); err != nil {
		return nil, err
	}
	return c, nil
}

// Describe returns the TCP canary spec.
func (c *tcpCanary) Describe() Spec {
	return Spec{Type: tcpType, Version: "1", Description: "TCP connect latency + reachability"}
}

// Run connects c.count times and reports connect-latency stats. A connect
// failure counts as loss; all-failed is Success=false (target unreachable).
func (c *tcpCanary) Run(ctx context.Context) (Result, error) {
	start := time.Now()
	addr := net.JoinHostPort(c.host, c.port)
	res := Result{Type: tcpType, Target: addr, StartedAt: start, Attributes: map[string]string{
		"network.transport": "tcp",
		"server.address":    c.host,
		"server.port":       c.port,
	}}

	dialer := net.Dialer{Timeout: c.timeout, Control: c.guard.DialControl(dialControl(c.dscp))}
	samples := make([]time.Duration, c.count)
	for i := 0; i < c.count; i++ {
		if ctx.Err() != nil {
			samples[i] = -1
			continue
		}
		t0 := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			samples[i] = -1
		} else {
			samples[i] = time.Since(t0)
			_ = conn.Close()
		}
		if i < c.count-1 {
			sleepCtx(ctx, c.spacing)
		}
	}
	res.Duration = time.Since(start)

	stats := computeLatencyStats(samples, c.count)
	res.Metrics = stats.latencyMetrics("connect")
	if stats.Received == 0 {
		res.Success = false
		res.Error = fmt.Sprintf("all %d TCP connects to %s failed", c.count, addr)
	} else {
		res.Success = true
	}
	return res, nil
}

// splitTarget resolves a target into host + port. The target may be host:port,
// otherwise the port comes from portParam.
func splitTarget(target, portParam string) (host, port string, err error) {
	if target == "" {
		return "", "", errors.New("target is required")
	}
	if h, p, e := net.SplitHostPort(target); e == nil {
		return h, p, nil
	}
	if portParam == "" {
		return "", "", fmt.Errorf("target %q has no port and no port param is set", target)
	}
	if n, e := strconv.Atoi(portParam); e != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("invalid port %q", portParam)
	}
	return target, portParam, nil
}
