package opendata

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// fakeResolver implements TXTResolver from an in-memory map.
type fakeResolver struct {
	txts map[string][]string
	err  error
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.txts[name], nil
}

// fakeGeo implements GeoReader from an in-memory map.
type fakeGeo struct {
	res map[netip.Addr]GeoResult
	err error
}

func (f fakeGeo) LookupGeo(addr netip.Addr) (GeoResult, bool, error) {
	if f.err != nil {
		return GeoResult{}, false, f.err
	}
	r, ok := f.res[addr]
	return r, ok, nil
}

// fakeDoer implements Doer from a function and counts calls.
type fakeDoer struct {
	fn    func(*http.Request) (*http.Response, error)
	calls int
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.calls++
	return f.fn(req)
}

func jsonResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

// fakeSource is a configurable Source for Enricher tests.
type fakeSource struct {
	desc  Descriptor
	fn    func(addr netip.Addr, e *Enrichment) error
	calls int
}

func (f *fakeSource) Descriptor() Descriptor { return f.desc }

func (f *fakeSource) Enrich(_ context.Context, addr netip.Addr, e *Enrichment) error {
	f.calls++
	return f.fn(addr, e)
}

func statusByName(ss []SourceStatus, name string) (SourceStatus, bool) {
	for _, s := range ss {
		if s.Descriptor.Name == name {
			return s, true
		}
	}
	return SourceStatus{}, false
}
