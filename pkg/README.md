# pkg/

Shared, public Go libraries — packages intended to be importable by external
consumers without pulling in control-plane internals (unlike `internal/`, which
the Go toolchain keeps private to this module).

## Status (S0)

Empty. Populated as stable, reusable surfaces emerge — for example generated
protobuf SDK types or a thin client library. Keep this directory free of
control-plane business logic.
