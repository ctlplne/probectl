// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bus

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/nats-io/nats.go"

	"github.com/ctlplne/probectl/internal/crypto"
)

// Security is the Kafka transport policy (U-010): telemetry on the broker hop
// is TLS by default. A kafka-mode bus WITHOUT TLS is refused unless the
// operator sets the explicit AllowPlaintext dev flag — production profiles
// never set it.
type Security struct {
	// TLSEnabled turns on TLS to the brokers (hardened policy: TLS 1.2+,
	// AEAD-only, verification always on — internal/crypto).
	TLSEnabled bool
	// CAFile optionally pins a private CA bundle for the brokers.
	CAFile string
	// CertFile/KeyFile optionally present a client certificate (broker mTLS).
	CertFile string
	KeyFile  string

	// SASLMechanism is "", "plain", "scram-sha-256" or "scram-sha-512";
	// SASLUser/SASLPassword authenticate when set.
	SASLMechanism string
	SASLUser      string
	SASLPassword  string

	// AllowPlaintext is the EXPLICIT dev-only escape hatch
	// (*_BUS_ALLOW_PLAINTEXT=true): without it, kafka mode requires TLS.
	AllowPlaintext bool

	// MaxBufferedRecords bounds the async producer's in-flight buffer
	// (U-004); 0 = DefaultMaxBuffered. When full, new records are shed
	// with ErrPublishShed and counted.
	MaxBufferedRecords int

	// Stream is the durability policy for the nats mode's JetStream streams
	// and durable consumers (DPR-119); zero values take the defaults. It is
	// ignored by the other modes.
	Stream StreamPolicy
}

// Validate enforces the fail-closed policy for every networked bus mode
// (kafka and nats — the durable lightweight transport is held to the same
// rule, DPR-119).
func (s Security) Validate() error {
	if !s.TLSEnabled && !s.AllowPlaintext {
		return errors.New("bus: a networked bus without TLS is refused (U-010) — enable TLS " +
			"(BUS_TLS_ENABLED=true, optionally BUS_TLS_CA_FILE / client cert + credentials) " +
			"or set the explicit dev-only BUS_ALLOW_PLAINTEXT=true flag")
	}
	switch strings.ToLower(s.SASLMechanism) {
	case "", "plain", "scram-sha-256", "scram-sha-512":
	default:
		return fmt.Errorf("bus: unknown SASL mechanism %q (want plain|scram-sha-256|scram-sha-512)", s.SASLMechanism)
	}
	if s.SASLMechanism != "" && (s.SASLUser == "" || s.SASLPassword == "") {
		return errors.New("bus: SASL mechanism set without user/password")
	}
	if (s.CertFile == "") != (s.KeyFile == "") {
		return errors.New("bus: client cert and key must be set together")
	}
	return nil
}

// kgoOpts renders the policy as franz-go options.
func (s Security) kgoOpts() ([]kgo.Opt, error) {
	var opts []kgo.Opt
	if s.MaxBufferedRecords > 0 {
		opts = append(opts, kgo.MaxBufferedRecords(s.MaxBufferedRecords))
	}
	if s.TLSEnabled {
		cfg, err := s.tlsConfig()
		if err != nil {
			return nil, err
		}
		opts = append(opts, kgo.DialTLSConfig(cfg))
	}
	if mech, err := s.saslMechanism(); err != nil {
		return nil, err
	} else if mech != nil {
		opts = append(opts, kgo.SASL(mech))
	}
	return opts, nil
}

// natsOpts renders the same policy as NATS options (DPR-119). NATS
// authenticates with a user and password rather than a SASL mechanism, so a
// SCRAM mechanism is refused here instead of being silently ignored: a
// credential the server will not see is the same as no credential.
func (s Security) natsOpts() ([]nats.Option, error) {
	var opts []nats.Option
	if s.TLSEnabled {
		cfg, err := s.tlsConfig()
		if err != nil {
			return nil, err
		}
		opts = append(opts, nats.Secure(cfg))
	}
	switch strings.ToLower(s.SASLMechanism) {
	case "", "plain":
		if s.SASLUser != "" {
			opts = append(opts, nats.UserInfo(s.SASLUser, s.SASLPassword))
		}
	default:
		return nil, fmt.Errorf("bus: nats mode authenticates with a user and password; "+
			"BUS_SASL_MECHANISM=%q is a Kafka mechanism NATS cannot use — set it to plain (or leave it empty) "+
			"with BUS_SASL_USER / BUS_SASL_PASSWORD, or use client-certificate authentication", s.SASLMechanism)
	}
	return opts, nil
}

func (s Security) tlsConfig() (*tls.Config, error) {
	var cfg *tls.Config
	if s.CertFile != "" {
		// Broker mTLS: hardened client config presenting our pair, trusting CAFile.
		c, err := crypto.ClientMTLSConfig(s.CertFile, s.KeyFile, s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("bus: kafka client mTLS: %w", err)
		}
		return c, nil
	}
	cfg = crypto.HardenedClientTLSConfig()
	if s.CAFile != "" {
		pool, err := crypto.LoadCertPool(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("bus: kafka CA: %w", err)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func (s Security) saslMechanism() (sasl.Mechanism, error) {
	switch strings.ToLower(s.SASLMechanism) {
	case "":
		return nil, nil
	case "plain":
		return plain.Auth{User: s.SASLUser, Pass: s.SASLPassword}.AsMechanism(), nil
	case "scram-sha-256":
		return scram.Auth{User: s.SASLUser, Pass: s.SASLPassword}.AsSha256Mechanism(), nil
	case "scram-sha-512":
		return scram.Auth{User: s.SASLUser, Pass: s.SASLPassword}.AsSha512Mechanism(), nil
	default:
		return nil, fmt.Errorf("bus: unknown SASL mechanism %q", s.SASLMechanism)
	}
}

// SecurityFromEnv reads the policy from <prefix>_TLS_ENABLED, _TLS_CA_FILE,
// _TLS_CERT_FILE, _TLS_KEY_FILE, _SASL_MECHANISM, _SASL_USER, _SASL_PASSWORD
// and _ALLOW_PLAINTEXT. The agents use it with their PROBECTL_<AGENT>_BUS
// prefix; the control plane loads the same fields via internal/config.
func SecurityFromEnv(getenv func(string) string, prefix string) Security {
	return Security{
		TLSEnabled:         getenv(prefix+"_TLS_ENABLED") == "true",
		CAFile:             getenv(prefix + "_TLS_CA_FILE"),
		CertFile:           getenv(prefix + "_TLS_CERT_FILE"),
		KeyFile:            getenv(prefix + "_TLS_KEY_FILE"),
		SASLMechanism:      getenv(prefix + "_SASL_MECHANISM"),
		SASLUser:           getenv(prefix + "_SASL_USER"),
		SASLPassword:       getenv(prefix + "_SASL_PASSWORD"),
		AllowPlaintext:     getenv(prefix+"_ALLOW_PLAINTEXT") == "true",
		MaxBufferedRecords: MaxBufferedFromEnv(getenv, prefix),
		Stream: StreamPolicy{
			MaxAge:            durationFromEnv(getenv, prefix+"_STREAM_MAX_AGE"),
			Replicas:          intFromEnv(getenv, prefix+"_STREAM_REPLICAS"),
			InactiveThreshold: durationFromEnv(getenv, prefix+"_CONSUMER_IDLE"),
		},
	}
}

// MaxBufferedFromEnv parses <prefix>_MAX_BUFFERED for SecurityFromEnv callers
// (0/unset/invalid = the bus default).
func MaxBufferedFromEnv(getenv func(string) string, prefix string) int {
	n := 0
	for _, r := range getenv(prefix + "_MAX_BUFFERED") {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
		if n > 10_000_000 {
			return 10_000_000
		}
	}
	return n
}

// durationFromEnv reads an optional Go duration; anything unset or unparseable
// leaves the zero value, which means "the package default".
func durationFromEnv(getenv func(string) string, key string) time.Duration {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0
	}
	return d
}

// intFromEnv reads an optional positive integer; 0 means "the package default".
func intFromEnv(getenv func(string) string, key string) int {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}
