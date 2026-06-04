// Package otel holds probectl's OpenTelemetry semantic-convention mapping. S6 seeds
// the canonical Result -> OTel resource/attribute mapping (ResultAttributes) and
// the convention names, so every signal is OTel-shaped from its first emission
// (docs/otel-mapping.md; a CI conformance test enforces it). S22 builds the OTLP
// receivers/exporters + OBI on top of this — exposing signals as OTLP rather than
// remapping a divergent model.
package otel
