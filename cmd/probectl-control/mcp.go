package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/control"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// runMCPStdio runs the MCP server over stdio — the local transport (e.g. for
// Claude Desktop). The token comes from PROBECTL_MCP_TOKEN. The caller has already
// pointed the logger at stderr so stdout stays a clean JSON-RPC channel.
func runMCPStdio(cfg *config.Config, log *slog.Logger, db *store.DB) error {
	token := os.Getenv("PROBECTL_MCP_TOKEN")
	if token == "" {
		return fmt.Errorf("PROBECTL_MCP_TOKEN is required for mcp-stdio")
	}
	p, err := control.NewMCPAuthenticator(db.Pool()).Authenticate(context.Background(), token)
	if err != nil {
		return fmt.Errorf("authenticate mcp token: %w", err)
	}
	pathStore, err := pathstore.New(cfg.PathStoreMode, cfg.PathStoreURL)
	if err != nil {
		return fmt.Errorf("path store: %w", err)
	}
	defer pathStore.Close()

	srv := control.NewMCPServer(cfg, log, db.Pool(), pathStore, cfg.MCPRatePerMin, nil)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("mcp stdio session", "tenant", p.TenantID, "user", p.UserID)
	return srv.ServeStdio(ctx, os.Stdin, os.Stdout, p)
}

// runMCPToken mints an MCP bearer token for a user and prints it once to stdout.
func runMCPToken(log *slog.Logger, db *store.DB, args []string) error {
	fs := flag.NewFlagSet("mcp-token", flag.ContinueOnError)
	tenant := fs.String("tenant", tenancy.DefaultTenantID.String(), "tenant id")
	user := fs.String("user", "", "user id (uuid) the token acts as (required)")
	name := fs.String("name", "mcp", "a label for the token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *user == "" {
		return fmt.Errorf("mcp-token: --user <uuid> is required")
	}
	token, err := auth.RandomToken()
	if err != nil {
		return err
	}
	id, err := store.NewMCPTokens(db.Pool()).Create(context.Background(), *tenant, *user, *name, crypto.Hash([]byte(token)))
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	log.Info("created mcp token", "id", id, "tenant", *tenant, "user", *user, "name", *name)
	fmt.Println(token) // the secret is shown once
	return nil
}

// serveMCPHTTP runs the MCP HTTP transport (TLS, bearer-authenticated) until the
// context is canceled, then drains.
func serveMCPHTTP(ctx context.Context, addr string, tlsCfg *tls.Config, h http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:         addr,
		Handler:      h,
		TLSConfig:    tlsCfg,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		log.Info("mcp http listening", "addr", addr)
		err := srv.ListenAndServeTLS("", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
