package device

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	gnmipb "github.com/imfeelingtheagi/probectl/internal/gen/gnmi"
)

// ocLeafMetrics maps OpenConfig leaf names (the final path element under
// /interfaces/interface/state/...) onto the shared device metric names — the
// same names the SNMP poller emits, so the two transports are interchangeable
// downstream.
var ocLeafMetrics = map[string]struct {
	name string
	unit string
}{
	"in-octets":    {MetricIfInOctets, "octets"},
	"out-octets":   {MetricIfOutOctets, "octets"},
	"in-errors":    {MetricIfInErrors, "packets"},
	"out-errors":   {MetricIfOutErrors, "packets"},
	"in-discards":  {MetricIfInDiscards, "packets"},
	"out-discards": {MetricIfOutDiscards, "packets"},
	"oper-status":  {MetricIfOperStatus, ""},
}

// gnmiCollector maintains one device's Subscribe stream: dial (TLS verified by
// default), subscribe SAMPLE on the configured paths, normalize notifications,
// and reconnect with backoff until the context ends.
type gnmiCollector struct {
	dev Target
	// cred is the static credential (tests). credFn, when set, RE-RESOLVES the
	// credential on every (re)connect so rotated secrets apply without an
	// agent restart (S41); a failing resolve fails the attempt — fail closed —
	// and the run loop's backoff retries.
	cred   Credential
	credFn func() (Credential, error)
	tenant string
	agent  string
	emit   Emitter
	log    *slog.Logger

	// dialOpts lets the mock-target test inject a bufconn dialer; production
	// always builds its own transport credentials. targetOverride replaces the
	// host:port target (bufconn's passthrough address in tests).
	dialOpts       []grpc.DialOption
	targetOverride string
}

// run is the reconnect loop. Each failure backs off exponentially (1s..30s);
// a successful stream resets the backoff.
func (c *gnmiCollector) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := c.streamOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.log.Warn("gnmi stream ended; reconnecting",
				"device", c.dev.Address, "backoff", backoff.String(), "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// streamOnce dials, subscribes, and pumps notifications until the stream ends.
func (c *gnmiCollector) streamOnce(ctx context.Context) error {
	cred := c.cred
	if c.credFn != nil {
		var err error
		if cred, err = c.credFn(); err != nil {
			return fmt.Errorf("gnmi credential resolve %s: %w", c.dev.Address, err)
		}
	}
	opts, err := c.transport()
	if err != nil {
		return err
	}
	opts = append(opts, c.dialOpts...)
	target := fmt.Sprintf("%s:%d", c.dev.Address, c.dev.Port)
	if c.targetOverride != "" {
		target = c.targetOverride
	}
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		return fmt.Errorf("gnmi dial %s: %w", target, err)
	}
	defer conn.Close()

	sctx := ctx
	if cred.Username != "" {
		sctx = metadata.AppendToOutgoingContext(ctx,
			"username", cred.Username, "password", cred.Password)
	}
	stream, err := gnmipb.NewGNMIClient(conn).Subscribe(sctx)
	if err != nil {
		return fmt.Errorf("gnmi subscribe %s: %w", target, err)
	}
	if err := stream.Send(c.subscribeRequest()); err != nil {
		return fmt.Errorf("gnmi subscribe request %s: %w", target, err)
	}
	c.log.Info("gnmi subscribed", "device", c.dev.Address,
		"paths", len(c.dev.GNMI.Paths), "sample", c.dev.GNMI.SampleInterval.String())

	for {
		resp, err := stream.Recv()
		if err != nil {
			return err
		}
		if n := resp.GetUpdate(); n != nil {
			if ms := c.normalize(n); len(ms) > 0 {
				if err := c.emit.Emit(ctx, ms); err != nil {
					c.log.Error("gnmi emit failed", "device", c.dev.Address, "error", err.Error())
				}
			}
		}
	}
}

// transport builds the gRPC transport credentials: TLS with certificate
// verification by default (system roots or ca_file) — never skip-verify
// (CLAUDE.md §7 guardrail 12). Plaintext is an explicit lab opt-in.
func (c *gnmiCollector) transport() ([]grpc.DialOption, error) {
	if c.dev.GNMI.Plaintext {
		c.log.Warn("gnmi dialing PLAINTEXT (explicit lab opt-in; prefer TLS)", "device", c.dev.Address)
		return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.dev.GNMI.CAFile != "" {
		pem, err := os.ReadFile(c.dev.GNMI.CAFile)
		if err != nil {
			return nil, fmt.Errorf("gnmi %s: read ca_file: %w", c.dev.Address, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("gnmi %s: ca_file contains no certificates", c.dev.Address)
		}
		cfg.RootCAs = pool
	}
	return []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(cfg))}, nil
}

// subscribeRequest builds the STREAM/SAMPLE SubscriptionList for the
// configured OpenConfig paths.
func (c *gnmiCollector) subscribeRequest() *gnmipb.SubscribeRequest {
	subs := make([]*gnmipb.Subscription, 0, len(c.dev.GNMI.Paths))
	for _, p := range c.dev.GNMI.Paths {
		subs = append(subs, &gnmipb.Subscription{
			Path:           parsePath(p),
			Mode:           gnmipb.SubscriptionMode_SAMPLE,
			SampleInterval: uint64(c.dev.GNMI.SampleInterval.Nanoseconds()),
		})
	}
	return &gnmipb.SubscribeRequest{
		Request: &gnmipb.SubscribeRequest_Subscribe{
			Subscribe: &gnmipb.SubscriptionList{
				Subscription: subs,
				Mode:         gnmipb.SubscriptionList_STREAM,
				Encoding:     gnmipb.Encoding_PROTO,
			},
		},
	}
}

// normalize maps one Notification onto device metrics: the interface name
// comes from the path key (interface[name=...]); the leaf name selects the
// metric. Unmapped leaves are skipped — devices stream plenty probectl does
// not chart.
func (c *gnmiCollector) normalize(n *gnmipb.Notification) []Metric {
	ts := time.Unix(0, n.GetTimestamp())
	if n.GetTimestamp() == 0 {
		ts = time.Now()
	}
	var out []Metric
	for _, u := range n.GetUpdate() {
		elems := joinElems(n.GetPrefix(), u.GetPath())
		if len(elems) == 0 {
			continue
		}
		leaf := elems[len(elems)-1].GetName()
		spec, ok := ocLeafMetrics[leaf]
		if !ok {
			continue
		}
		val, ok := typedValueFloat(leaf, u.GetVal())
		if !ok {
			continue
		}
		m := Metric{
			TenantID: c.tenant, AgentID: c.agent,
			Device: c.dev.Address, DeviceName: targetName(n), Source: SourceGNMI,
			IfName: pathKey(elems, "interface", "name"),
			Name:   spec.name, Value: val, Unit: spec.unit, At: ts,
		}
		out = append(out, m)
	}
	return out
}

// typedValueFloat coerces the gNMI TypedValue variants probectl maps. The
// oper-status leaf arrives as a string ("UP"/"DOWN"/...).
func typedValueFloat(leaf string, v *gnmipb.TypedValue) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch tv := v.GetValue().(type) {
	case *gnmipb.TypedValue_UintVal:
		return float64(tv.UintVal), true
	case *gnmipb.TypedValue_IntVal:
		return float64(tv.IntVal), true
	case *gnmipb.TypedValue_DoubleVal:
		return tv.DoubleVal, true
	case *gnmipb.TypedValue_BoolVal:
		return boolFloat(tv.BoolVal), true
	case *gnmipb.TypedValue_StringVal:
		if leaf == "oper-status" {
			return boolFloat(strings.EqualFold(tv.StringVal, "UP")), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// parsePath converts a slash path with optional [key=value] qualifiers into a
// gNMI Path (a deliberately small parser for OpenConfig-style config paths;
// not a full gNMI path grammar).
func parsePath(p string) *gnmipb.Path {
	var elems []*gnmipb.PathElem
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		if part == "" {
			continue
		}
		e := &gnmipb.PathElem{}
		if i := strings.IndexByte(part, '['); i >= 0 {
			e.Name = part[:i]
			e.Key = map[string]string{}
			for _, kv := range strings.Split(strings.Trim(part[i:], "[]"), "][") {
				if j := strings.IndexByte(kv, '='); j > 0 {
					e.Key[kv[:j]] = kv[j+1:]
				}
			}
		} else {
			e.Name = part
		}
		elems = append(elems, e)
	}
	return &gnmipb.Path{Elem: elems}
}

// joinElems concatenates prefix + path elems.
func joinElems(prefix, path *gnmipb.Path) []*gnmipb.PathElem {
	out := make([]*gnmipb.PathElem, 0, len(prefix.GetElem())+len(path.GetElem()))
	out = append(out, prefix.GetElem()...)
	return append(out, path.GetElem()...)
}

// pathKey returns the key value of the named element (e.g. the interface name
// in interfaces/interface[name=eth0]/state/...).
func pathKey(elems []*gnmipb.PathElem, elem, key string) string {
	for _, e := range elems {
		if e.GetName() == elem {
			return e.GetKey()[key]
		}
	}
	return ""
}

// targetName extracts the notification prefix target (device-asserted name).
func targetName(n *gnmipb.Notification) string {
	return n.GetPrefix().GetTarget()
}
