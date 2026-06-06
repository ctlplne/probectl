package bus

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/twmb/franz-go/pkg/kgo"
	"github.com/twmb/franz-go/pkg/sasl"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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
}

// Validate enforces the fail-closed policy for kafka mode.
func (s Security) Validate() error {
	if !s.TLSEnabled && !s.AllowPlaintext {
		return errors.New("bus: kafka without TLS is refused (U-010) — enable TLS " +
			"(BUS_TLS_ENABLED=true, optionally BUS_TLS_CA_FILE / client cert + SASL) " +
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
		TLSEnabled:     getenv(prefix+"_TLS_ENABLED") == "true",
		CAFile:         getenv(prefix + "_TLS_CA_FILE"),
		CertFile:       getenv(prefix + "_TLS_CERT_FILE"),
		KeyFile:        getenv(prefix + "_TLS_KEY_FILE"),
		SASLMechanism:  getenv(prefix + "_SASL_MECHANISM"),
		SASLUser:       getenv(prefix + "_SASL_USER"),
		SASLPassword:   getenv(prefix + "_SASL_PASSWORD"),
		AllowPlaintext: getenv(prefix+"_ALLOW_PLAINTEXT") == "true",
	}
}
