// Package pipeline is probectl's result pipeline (S6): it converts probe Results to
// OTel-aligned time series (ResultToSeries) and runs the control-plane Consumer
// that drains the result bus and writes to the TSDB. The flow is
// agent -> gRPC StreamResults -> control-plane ingest -> bus -> Consumer -> TSDB.
package pipeline
