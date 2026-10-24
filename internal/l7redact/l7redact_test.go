// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package l7redact

import (
	"reflect"
	"strings"
	"testing"
)

// tokenShaped builds a credential-prefixed test segment at run time, so no
// key-shaped literal ever sits in the source (secret scanning reads history).
func tokenShaped(prefix, body string) string { return prefix + body }

// tmpl is TemplateRoute's route alone.
func tmpl(path string) string {
	out, _ := TemplateRoute(path)
	return out
}

func TestTemplateRoute(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"/", "/"},
		{"/healthz", "/healthz"},
		{"/api/v1/orders", "/api/v1/orders"},
		{"/api/v2beta1/things", "/api/v2beta1/things"},
		// numeric, contract-number, UUID, hex, long-token segments
		{"/patients/48213", "/patients/{id}"},
		{"/contracts/W56HZV-23-C-0123/drawings", "/contracts/{id}/drawings"},
		{"/orders/550e8400-e29b-41d4-a716-446655440000/items", "/orders/{id}/items"},
		{"/blobs/a1b2c3d4e5f6", "/blobs/{id}"},
		{"/commits/0123456789abcdef0123456789abcdef01234567", "/commits/{id}"},
		{"/s/eyJhbGciOiJIUzI1NiJ9", "/s/{id}"},
		{"/reset/kXbQpzRwTvLmNa", "/reset/{id}"},
		{"/users/user_42/profile", "/users/{id}/profile"},
		// query strings, fragments, matrix params never survive
		{"/search?q=alice&token=s3cr3t", "/search"},
		{"/page#section-2", "/page"},
		{"/cart;jsessionid=ABC123DEF/view", "/cart/view"},
		// encoded / structured content is never kept
		{"/mail/alice%40example.com", "/mail/{id}"},
		{"/mail/alice@example.com", "/mail/{id}"},
		// dotted segments are judged label by label
		{"/files/report-2024.pdf", "/files/{id}.pdf"},
		{"/files/48213.json", "/files/{id}.json"},
		{"/hosts/10.0.0.1", "/hosts/{id}"},
		{"/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Check"},
		{"/v1/projects/p:batchGet", "/v1/projects/p:batchGet"},
		{"/v1/jobs/123:cancel", "/v1/jobs/{id}:cancel"},
		// word segments and short product names survive
		{"/auth/oauth2/callback", "/auth/oauth2/callback"},
		{"/aws/ec2/instances", "/aws/ec2/instances"},
		{"/service-configurations/default", "/service-configurations/default"},
		{"/pkg.Service/GetUserProfileSettings", "/pkg.Service/GetUserProfileSettings"},
		// idempotent on already-templated routes
		{"/patients/{id}", "/patients/{id}"},
		// review S6: short mixed ids, digit-free hex, base64-ish, token prefixes
		{"/users/user123", "/users/{id}"},
		{"/acct/acct42/statements", "/acct/{id}/statements"},
		{"/patients/ABCD123", "/patients/{id}"},
		{"/blobs/deadbeefcafebabe", "/blobs/{id}"},
		{"/download/YWxpY2U", "/download/{id}"},
		{"/x/MzEyMw", "/x/{id}"},
		{"/x/AbCdEfGhIjKlMnOp", "/x/{id}"},
		{"/x/" + tokenShaped("ghp_", "abcdef"), "/x/{id}"},
		{"/x/" + tokenShaped("sk-", "abcdefghijk"), "/x/{id}"},
		{"/keys/" + tokenShaped("AK"+"IA", "EXAMPLEEXAMPLE"), "/keys/{id}"},
		{"/api/v1/k8s/clusters", "/api/v1/k8s/clusters"},
		{"/assets/x509/sha256", "/assets/x509/sha256"},
		{"/ios/iPhone/settings", "/ios/iPhone/settings"},
		{"/apps/YouTube/watch", "/apps/YouTube/watch"},
		{"/macOS/README", "/macOS/README"},
		{"/v1/decade/facade", "/v1/decade/facade"},
	}
	for _, tc := range cases {
		if got := tmpl(tc.in); got != tc.want {
			t.Errorf("TemplateRoute(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if got := tmpl(tmpl(tc.in)); got != tc.want {
			t.Errorf("TemplateRoute is not idempotent on %q: %q", tc.in, got)
		}
	}
}

func TestTemplateRouteBounds(t *testing.T) {
	long := "/" + strings.Repeat("seg/", 100)
	got := tmpl(long)
	if n := strings.Count(got, "/"); n > maxRouteSegments+2 {
		t.Fatalf("segments not bounded: %d slashes in %q", n, got)
	}
	if !strings.HasSuffix(got, truncatedMarker) {
		t.Fatalf("truncated route lacks marker: %q", got)
	}
	wide := "/" + strings.Repeat("abcdefghij", 60)
	if got := tmpl(wide); len(got) > maxRouteBytes {
		t.Fatalf("route not byte-bounded: %d bytes", len(got))
	}
}

func TestModeOrdering(t *testing.T) {
	for _, tc := range []struct {
		mode, floor string
		looser      bool
	}{
		{ModeFull, ModeMetadata, true},
		{ModeHeaders, ModeMetadata, true},
		{ModeMetadata, ModeMetadata, false},
		{ModeLength, ModeMetadata, false},
		{ModeHeaders, ModeHeaders, false},
		{ModeFull, ModeHeaders, true},
		{"", ModeMetadata, false},       // empty = the metadata default
		{"bogus", ModeLength, true},     // unknown mode: always looser
		{ModeHeaders, "", true},         // empty floor = metadata
		{ModeHeaders, "nonsense", true}, // unknown floor = metadata
	} {
		if got := Looser(tc.mode, tc.floor); got != tc.looser {
			t.Errorf("Looser(%q, %q) = %v, want %v", tc.mode, tc.floor, got, tc.looser)
		}
	}
	if got := Stricter(ModeHeaders, ModeMetadata); got != ModeMetadata {
		t.Errorf("Stricter(headers, metadata) = %q", got)
	}
	if got := Stricter(ModeLength, ModeMetadata); got != ModeLength {
		t.Errorf("Stricter(length, metadata) = %q", got)
	}
	if got := Stricter("", ModeFull); got != ModeMetadata {
		t.Errorf("Stricter(\"\", full) = %q", got)
	}
}

func TestMinimize(t *testing.T) {
	cases := []struct {
		name   string
		in     Call
		mode   string
		want   Call
		fields []string
	}{
		{
			name:   "http1 metadata templates the route and drops the query",
			in:     Call{Protocol: "http1", Method: "POST", Resource: "/contracts/W56HZV-23-C-0123/drawings?sig=abc", Status: "201"},
			mode:   ModeMetadata,
			want:   Call{Protocol: "http1", Method: "POST", Resource: "/contracts/{id}/drawings", Status: "201"},
			fields: []string{"query", "identifier_segment"},
		},
		{
			name:   "http1 headers keeps segments but never the query",
			in:     Call{Protocol: "http1", Method: "GET", Resource: "/patients/48213?token=x", Status: "200"},
			mode:   ModeHeaders,
			want:   Call{Protocol: "http1", Method: "GET", Resource: "/patients/48213", Status: "200"},
			fields: []string{"query"},
		},
		{
			name:   "unknown http method becomes _OTHER",
			in:     Call{Protocol: "http2", Method: "XSECRETX", Resource: "/x", Status: "200"},
			mode:   ModeMetadata,
			want:   Call{Protocol: "http2", Method: OtherMethod, Resource: "/x", Status: "200"},
			fields: []string{"method"},
		},
		{
			name: "grpc method is templated like a route",
			in:   Call{Protocol: "grpc", Method: "pkg.v1.Orders/Get", Resource: "/pkg.v1.Orders/Get", Status: "0"},
			mode: ModeMetadata,
			want: Call{Protocol: "grpc", Method: "pkg.v1.Orders/Get", Resource: "/pkg.v1.Orders/Get", Status: "0"},
		},
		{
			name:   "sql statement text is dropped under metadata",
			in:     Call{Protocol: "postgresql", Method: "SELECT", Resource: "SELECT * FROM t WHERE id = ?", Status: "SELECT 1"},
			mode:   ModeMetadata,
			want:   Call{Protocol: "postgresql", Method: "SELECT", Resource: "", Status: "SELECT 1"},
			fields: []string{"statement"},
		},
		{
			name: "sql statement fingerprint survives under headers",
			in:   Call{Protocol: "postgresql", Method: "SELECT", Resource: "SELECT * FROM t WHERE id = ?", Status: "SELECT 1"},
			mode: ModeHeaders,
			want: Call{Protocol: "postgresql", Method: "SELECT", Resource: "SELECT * FROM t WHERE id = ?", Status: "SELECT 1"},
		},
		{
			name: "dns qname is the dns route and survives",
			in:   Call{Protocol: "dns", Method: "A", Resource: "api.example.com", Status: "NOERROR"},
			mode: ModeMetadata,
			want: Call{Protocol: "dns", Method: "A", Resource: "api.example.com", Status: "NOERROR"},
		},
		{
			name:   "unknown protocol keeps nothing free-form",
			in:     Call{Protocol: "smtp", Method: "MAIL FROM:<a@b>", Resource: "rcpt", Status: "250"},
			mode:   ModeMetadata,
			want:   Call{Protocol: ProtoOther, Method: OtherMethod, Resource: "", Status: "250"},
			fields: []string{"method", "resource", "protocol"},
		},
		{
			name:   "free-form status becomes _OTHER",
			in:     Call{Protocol: "http1", Method: "GET", Resource: "/", Status: "200 Authorization: Bearer x"},
			mode:   ModeMetadata,
			want:   Call{Protocol: "http1", Method: "GET", Resource: "/", Status: OtherMethod},
			fields: []string{"status"},
		},
		{
			name:   "full mode still strips the query",
			in:     Call{Protocol: "http1", Method: "GET", Resource: "/a?b=c", Status: "200"},
			mode:   ModeFull,
			want:   Call{Protocol: "http1", Method: "GET", Resource: "/a", Status: "200"},
			fields: []string{"query"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, strip := MinimizeWith(tc.in, tc.mode, Options{})
			if got != tc.want {
				t.Fatalf("Minimize = %+v, want %+v", got, tc.want)
			}
			if f := strip.Fields(); !reflect.DeepEqual(f, tc.fields) {
				t.Fatalf("strip fields = %v, want %v", f, tc.fields)
			}
			again, strip2 := MinimizeWith(got, tc.mode, Options{})
			if again != got || strip2 != 0 {
				t.Fatalf("Minimize not idempotent: %+v (strips %v)", again, strip2.Fields())
			}
		})
	}
}

func FuzzTemplateRoute(f *testing.F) {
	for _, s := range []string{"/a/b", "/patients/48213?x=y", "/x;y=z/{id}", "", "////", "/a.b:c-d_e"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := tmpl(s)
		if strings.ContainsAny(out, "?#;") {
			t.Fatalf("query/fragment/matrix survived: %q -> %q", s, out)
		}
		if len(out) > maxRouteBytes {
			t.Fatalf("unbounded route: %d bytes", len(out))
		}
		if again := tmpl(out); again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, out, again)
		}
	})
}

func TestProtocolEnumAndLabel(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"http1", "http1"}, {"", ""}, {"other", "other"},
		{"BODYCUI-CONTROLLED-7731 /patients/48213?ssn=1", ProtoOther},
	} {
		if got, _ := Protocol(tc.in); got != tc.want {
			t.Errorf("Protocol(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, ok := range []string{"nginx", "k8s-pod:0123456789ab/nginx@abcdef012345", "10.0.2.9", "2001:db8::1", "kworker/0:1", "(sd-pam)", "Web Content", "nginx.service"} {
		if got, st := Label(ok); got != ok || st != 0 {
			t.Errorf("Label(%q) = %q, want it kept", ok, got)
		}
	}
	for _, bad := range []string{`{"diagnosis":"x"}`, "/search?q=1", "a=b&c=d", "line\nbreak", strings.Repeat("a", 254), "café"} {
		if got, st := Label(bad); got != InvalidLabel || st != StripLabel {
			t.Errorf("Label(%q) = %q, want %q", bad, got, InvalidLabel)
		}
	}
	if got, _ := Enum("tcp", "tcp", "udp"); got != "tcp" {
		t.Errorf("Enum kept the vocabulary value as %q", got)
	}
	if got, st := Enum("tcp; DROP", "tcp", "udp"); got != ProtoOther || st != StripEnum {
		t.Errorf("Enum = %q", got)
	}
}
