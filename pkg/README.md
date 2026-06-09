# pkg/

Shared, public Go libraries — packages intended to be importable by external
consumers without pulling in control-plane internals (unlike `internal/`, which
the Go toolchain keeps private to this module).

## Status

Empty. It is populated only as stable, reusable surfaces emerge — for example a
thin client library or generated protobuf SDK types. Keep this directory free of
control-plane business logic.
