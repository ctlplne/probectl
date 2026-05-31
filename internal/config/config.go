// Package config loads and validates the netctl control-plane configuration
// from NETCTL_-prefixed environment variables. Every key is documented in
// docs/configuration.md (CLAUDE.md §6). Load reports all validation problems at
// once so a misconfiguration is fixed in a single pass.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the fully resolved, validated control-plane configuration.
type Config struct {
	// HTTP server.
	HTTPAddr        string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration

	// Database.
	DatabaseURL         string
	DatabaseMaxConns    int32
	DatabaseMinConns    int32
	DatabaseConnTimeout time.Duration

	// Migrations.
	MigrateOnBoot bool

	// Logging.
	LogLevel  string
	LogFormat string

	// Security posture. TLS terminates at the ingress until native TLS lands in
	// S3 (CLAUDE.md §7 guardrail 12); HSTS is set now so it is correct the moment
	// the API is served over HTTPS.
	HSTSEnabled bool
	HSTSMaxAge  time.Duration
}

// Load resolves configuration using the supplied getenv function (use
// LoadFromEnv for the process environment). All validation errors are joined
// and returned together.
func Load(getenv func(string) string) (*Config, error) {
	l := &loader{getenv: getenv}
	cfg := &Config{
		HTTPAddr:            l.str("NETCTL_HTTP_ADDR", ":8080"),
		ReadTimeout:         l.dur("NETCTL_HTTP_READ_TIMEOUT", 15*time.Second),
		WriteTimeout:        l.dur("NETCTL_HTTP_WRITE_TIMEOUT", 15*time.Second),
		IdleTimeout:         l.dur("NETCTL_HTTP_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout:     l.dur("NETCTL_SHUTDOWN_TIMEOUT", 15*time.Second),
		DatabaseURL:         l.str("NETCTL_DATABASE_URL", "postgres://netctl:netctl@localhost:5432/netctl?sslmode=disable"),
		DatabaseMaxConns:    int32(l.intRange("NETCTL_DATABASE_MAX_CONNS", 10, 1, 1000)),
		DatabaseMinConns:    int32(l.intRange("NETCTL_DATABASE_MIN_CONNS", 0, 0, 1000)),
		DatabaseConnTimeout: l.dur("NETCTL_DATABASE_CONNECT_TIMEOUT", 5*time.Second),
		MigrateOnBoot:       l.boolean("NETCTL_MIGRATE_ON_BOOT", false),
		LogLevel:            l.enum("NETCTL_LOG_LEVEL", "info", "debug", "info", "warn", "error"),
		LogFormat:           l.enum("NETCTL_LOG_FORMAT", "json", "json", "text"),
		HSTSEnabled:         l.boolean("NETCTL_HSTS_ENABLED", true),
		HSTSMaxAge:          l.dur("NETCTL_HSTS_MAX_AGE", 365*24*time.Hour),
	}

	if cfg.DatabaseMinConns > cfg.DatabaseMaxConns {
		l.errf("NETCTL_DATABASE_MIN_CONNS (%d) must be <= NETCTL_DATABASE_MAX_CONNS (%d)",
			cfg.DatabaseMinConns, cfg.DatabaseMaxConns)
	}
	if _, err := url.Parse(cfg.DatabaseURL); err != nil {
		l.errf("NETCTL_DATABASE_URL: invalid URL: %v", err)
	}

	if err := l.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadFromEnv resolves configuration from the process environment.
func LoadFromEnv() (*Config, error) { return Load(os.Getenv) }

// LogValue implements slog.LogValuer so the config can be logged at startup
// without leaking the database password (CLAUDE.md §7 guardrail 6).
func (c *Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("http_addr", c.HTTPAddr),
		slog.String("database_url", redactURL(c.DatabaseURL)),
		slog.Int("database_max_conns", int(c.DatabaseMaxConns)),
		slog.Bool("migrate_on_boot", c.MigrateOnBoot),
		slog.String("log_level", c.LogLevel),
		slog.String("log_format", c.LogFormat),
		slog.Bool("hsts_enabled", c.HSTSEnabled),
	)
}

func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "invalid-url"
	}
	if u.User != nil {
		if _, hasPW := u.User.Password(); hasPW {
			u.User = url.UserPassword(u.User.Username(), "xxxxx")
		}
	}
	return u.String()
}

// loader reads keys and accumulates validation errors.
type loader struct {
	getenv func(string) string
	errs   []error
}

func (l *loader) str(key, def string) string {
	if v := l.getenv(key); v != "" {
		return v
	}
	return def
}

func (l *loader) dur(key string, def time.Duration) time.Duration {
	v := l.getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		l.errf("%s: invalid duration %q: %v", key, v, err)
		return def
	}
	if d < 0 {
		l.errf("%s: must not be negative", key)
		return def
	}
	return d
}

func (l *loader) intRange(key string, def, lo, hi int) int {
	v := l.getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		l.errf("%s: invalid integer %q", key, v)
		return def
	}
	if n < lo || n > hi {
		l.errf("%s: %d out of range [%d,%d]", key, n, lo, hi)
		return def
	}
	return n
}

func (l *loader) boolean(key string, def bool) bool {
	v := l.getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		l.errf("%s: invalid boolean %q", key, v)
		return def
	}
	return b
}

func (l *loader) enum(key, def string, allowed ...string) string {
	v := l.getenv(key)
	if v == "" {
		return def
	}
	v = strings.ToLower(v)
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	l.errf("%s: %q is not one of [%s]", key, v, strings.Join(allowed, ", "))
	return def
}

func (l *loader) errf(format string, args ...any) {
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

func (l *loader) err() error { return errors.Join(l.errs...) }
