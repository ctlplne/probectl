# opendata test fixtures

## `geoip-test.mmdb`

A tiny **synthetic** MaxMind-DB used by `TestMMDBReader` so the real MMDB reader
is exercised on every run without shipping a licensed GeoLite2 database. The
data is fabricated by us (not MaxMind's), so there is no MaxMind licensing
concern — only the open MaxMind-DB *format* is used.

Contents: `8.8.8.0/24` and `1.1.1.0/24` → `{country.iso_code: US, city.names.en:
Mountain View, location: 37.386,-122.0838}`.

Regenerate (no repo dependency on the writer — it is fetched ad hoc):

```sh
cd "$(mktemp -d)" && go mod init gen >/dev/null
go get github.com/maxmind/mmdbwriter@latest
cat > main.go <<'GO'
package main
import (
  "net"; "os"
  "github.com/maxmind/mmdbwriter"
  "github.com/maxmind/mmdbwriter/mmdbtype"
)
func main() {
  tree, _ := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoLite2-City-Test", RecordSize: 24, IncludeReservedNetworks: true})
  rec := mmdbtype.Map{
    "country":  mmdbtype.Map{"iso_code": mmdbtype.String("US")},
    "city":     mmdbtype.Map{"names": mmdbtype.Map{"en": mmdbtype.String("Mountain View")}},
    "location": mmdbtype.Map{"latitude": mmdbtype.Float64(37.386), "longitude": mmdbtype.Float64(-122.0838)},
  }
  for _, c := range []string{"8.8.8.0/24", "1.1.1.0/24"} { _, nw, _ := net.ParseCIDR(c); tree.Insert(nw, rec) }
  f, _ := os.Create("geoip-test.mmdb"); defer f.Close(); tree.WriteTo(f)
}
GO
go run . && echo wrote geoip-test.mmdb
```
