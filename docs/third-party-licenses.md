# Third-party Go dependencies

This is the inventory of third-party Go modules that get compiled into
probectl's shipped binaries, with each module's detected license.

**Do not hand-edit the table below** — this whole file is generated. Running
`scripts/gen_third_party.sh` lists the real dependency graph
(`go list -deps ./...`, the modules actually linked into the binaries) and
rewrites this file plus the top-level `NOTICE`. Any manual change to the table
is overwritten the next time it runs; regenerate after a `go.mod` change.

How the License column is filled in: the script reads each module's cached
`LICENSE` file and guesses the license by keyword. That's a **heuristic, not a
legal determination** — so **verify it before any commercial or MSP resale**
(the AUP / provenance duty, `CLAUDE.md` §7.10). The full, authoritative license
texts ship inside each module (in the Go module cache or a vendor tree).

| Module | Version | License (detected) |
|---|---|---|
| `github.com/coreos/go-oidc/v3` | v3.18.0 | Apache-2.0 |
| `github.com/go-jose/go-jose/v4` | v4.1.4 | Apache-2.0 |
| `github.com/gosnmp/gosnmp` | v1.43.2 | BSD |
| `github.com/grpc-ecosystem/grpc-gateway/v2` | v2.28.0 | BSD |
| `github.com/jackc/pgpassfile` | v1.0.0 | MIT |
| `github.com/jackc/pgservicefile` | v0.0.0-20240606120523-5a60cdf6a761 | MIT |
| `github.com/jackc/pgx/v5` | v5.9.2 | MIT |
| `github.com/jackc/puddle/v2` | v2.2.2 | MIT |
| `github.com/klauspost/compress` | v1.18.6 | Apache-2.0 |
| `github.com/miekg/dns` | v1.1.72 | BSD |
| `github.com/oschwald/maxminddb-golang` | v1.13.1 | ISC |
| `github.com/pierrec/lz4/v4` | v4.1.26 | BSD |
| `github.com/twmb/franz-go/pkg/kmsg` | v1.13.1 | BSD |
| `github.com/twmb/franz-go` | v1.21.2 | BSD |
| `go.opentelemetry.io/proto/otlp` | v1.10.0 | Apache-2.0 |
| `golang.org/x/crypto` | v0.51.0 | BSD |
| `golang.org/x/net` | v0.55.0 | BSD |
| `golang.org/x/oauth2` | v0.36.0 | BSD |
| `golang.org/x/sync` | v0.20.0 | BSD |
| `golang.org/x/sys` | v0.45.0 | BSD |
| `golang.org/x/text` | v0.37.0 | BSD |
| `google.golang.org/genproto/googleapis/api` | v0.0.0-20260226221140-a57be14db171 | Apache-2.0 |
| `google.golang.org/genproto/googleapis/rpc` | v0.0.0-20260226221140-a57be14db171 | Apache-2.0 |
| `google.golang.org/grpc` | v1.81.1 | Apache-2.0 |
| `google.golang.org/protobuf` | v1.36.11 | BSD |
| `gopkg.in/yaml.v3` | v3.0.1 | Apache-2.0 |
