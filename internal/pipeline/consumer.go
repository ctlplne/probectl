package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// DefaultGroup is the consumer-group name for the control-plane result pipeline.
const DefaultGroup = "probectl-control"

// Consumer drains result messages from the bus and writes them to the TSDB.
type Consumer struct {
	bus   bus.Bus
	tsdb  tsdb.Writer
	group string
	log   *slog.Logger
}

// NewConsumer builds the result-pipeline consumer.
func NewConsumer(b bus.Bus, w tsdb.Writer, group string, log *slog.Logger) *Consumer {
	if group == "" {
		group = DefaultGroup
	}
	return &Consumer{bus: b, tsdb: w, group: group, log: log}
}

// resultTopics are the bus topics carrying resultv1.Result that the pipeline
// drains into the TSDB. Network-plane probe results (S6), endpoint/DEM results
// (S37) and real-user page views (S47b) share the canonical result schema, so
// one handler serves all three. Each topic gets its own consumer group so
// their offsets are independent.
func (c *Consumer) resultTopics() []topicGroup {
	return []topicGroup{
		{topic: bus.NetworkResultsTopic, group: c.group},
		{topic: bus.EndpointResultsTopic, group: c.group + "-endpoint"},
		{topic: bus.RUMEventsTopic, group: c.group + "-rum"}, // RUM vitals → dashboards
	}
}

type topicGroup struct{ topic, group string }

// Run subscribes to every result topic and writes each result to the TSDB until
// ctx is canceled. It blocks. The subscriptions run concurrently; a fatal error
// on any one cancels the rest and is returned.
func (c *Consumer) Run(ctx context.Context) error {
	subs := c.resultTopics()
	topics := make([]string, len(subs))
	for i, s := range subs {
		topics[i] = s.topic
	}
	c.log.Info("result pipeline consumer starting", "topics", topics, "group", c.group)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, len(subs))
	for _, s := range subs {
		wg.Add(1)
		go func(s topicGroup) {
			defer wg.Done()
			if err := c.bus.Subscribe(ctx, s.topic, s.group, c.handle); err != nil && ctx.Err() == nil {
				c.log.Error("result subscription failed", "topic", s.topic, "error", err.Error())
				errs <- err
				cancel() // one topic's fatal error stops the others
			}
		}(s)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err // a clean ctx cancel pushes nothing → returns nil
		}
	}
	return nil
}

// handle decodes one result and writes its series. Malformed messages and
// transient write failures are logged and dropped (best-effort) rather than
// blocking the stream; durable retry/redelivery is a later hardening step.
func (c *Consumer) handle(ctx context.Context, msg bus.Message) error {
	var r resultv1.Result
	if err := proto.Unmarshal(msg.Value, &r); err != nil {
		c.log.Error("dropping malformed result", "error", err.Error())
		return nil
	}
	if err := c.tsdb.Write(ctx, ResultToSeries(&r)); err != nil {
		c.log.Error("tsdb write failed", "tenant_id", r.GetTenantId(), "agent_id", r.GetAgentId(), "error", err.Error())
		return nil
	}
	return nil
}
