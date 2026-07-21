// The integration-test module. Black-box tests live here and exercise the
// running services over their public interfaces against the real dev stack
// (deploy/compose/dev.yml). Keeping them in a separate module isolates heavy
// test-only dependencies (Kafka/ClickHouse/Postgres drivers, testcontainers,
// ...) from the production module added in S6+.
module github.com/imfeelingtheagi/probectl/test

go 1.26.5

require github.com/imfeelingtheagi/probectl v0.5.0

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.9.2 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.37.0 // indirect
)
