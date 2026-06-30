module github.com/imfeelingtheagi/probectl

// Pinned to the official go1.26.4 release (sumdb-verified on download —
// docs/build/toolchain.md). The exact patch in the go directive keeps
// govulncheck's stdlib attribution honest (Sprint 25): a bare "go 1.26"
// scans as 1.26.0 and false-flags every already-patched stdlib CVE.
go 1.26.4

require (
	github.com/cilium/ebpf v0.22.0
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/jackc/pgx/v5 v5.9.2
	github.com/klauspost/compress v1.18.6
	github.com/miekg/dns v1.1.72
	github.com/oschwald/maxminddb-golang v1.13.1
	github.com/twmb/franz-go v1.21.2
	github.com/twmb/franz-go/pkg/kfake v0.0.0-20260515175617-8268a5d078c0
	github.com/twmb/franz-go/pkg/kmsg v1.13.1
	go.opentelemetry.io/proto/otlp v1.10.0
	golang.org/x/net v0.55.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.20.0
	golang.org/x/sys v0.45.0
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/gosnmp/gosnmp v1.43.2
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260226221140-a57be14db171 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)
