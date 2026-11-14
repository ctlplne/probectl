// The integration-test module. Black-box tests live here and exercise the
// running services over their public interfaces against the real dev stack
// (deploy/compose/dev.yml). Keeping them in a separate module isolates heavy
// test-only dependencies (Kafka/ClickHouse/Postgres drivers, testcontainers,
// ...) from the production module added in S6+.
module github.com/ctlplne/probectl/test

go 1.26.11

require (
	github.com/ctlplne/probectl v0.6.5
	github.com/jackc/pgx/v5 v5.9.2
)

require (
	github.com/coreos/go-oidc/v3 v3.18.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/gosnmp/gosnmp v1.47.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/nats-io/nats.go v1.53.1 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/oschwald/maxminddb-golang v1.13.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/twmb/franz-go v1.21.2 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.13.1 // indirect
	go.opentelemetry.io/proto/otlp v1.11.1 // indirect
	golang.org/x/crypto v0.58.1-0.20261009181718-2f1f834330b2 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc // indirect
	google.golang.org/grpc v1.84.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
