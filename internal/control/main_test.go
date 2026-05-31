package control

import (
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/config"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/store"
)

func TestMain(m *testing.M) {
	// Keep test output clean: discard server logs.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func testServer(pinger store.Pinger) *Server {
	cfg := &config.Config{
		HTTPAddr:    ":0",
		HSTSEnabled: true,
		HSTSMaxAge:  time.Hour,
	}
	return New(cfg, logging.New(io.Discard, "error", "json"), pinger)
}
