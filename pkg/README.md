# pkg/

Shared, public Go libraries — packages intended to be importable by external
consumers without pulling in control-plane internals. The split is enforced by
the Go toolchain itself: the compiler refuses any import of an `internal/`
package from outside this module, so `pkg/` is the one deliberate shelf of
exported code — putting something here is a publishing decision, not a file
move.

## Packages

- [`sdk`](sdk/sdk.gen.go): the Go API client generated from the control-plane
  OpenAPI specification. Configure it with the deployment's HTTPS URL, an API
  token, and an HTTP client that trusts the deployment's certificate authority
  when using a private CA.
- [`transport`](transport/transport.go): the SDK's HTTP client and bounded
  response reader, with certificate verification and a TLS 1.2 minimum.

Both packages are MPL-2.0 and import no `internal/` or `ee/` packages; the SDK
license-boundary test checks that dependency boundary. Generated protobuf Go
currently lives in `internal/gen/`, private on purpose. Keep this directory free
of control-plane business logic.
