// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/httpbody"
)

const (
	expectedCLIResponseBodyLimit      = int64(32 << 20)
	expectedCLIErrorResponseBodyLimit = int64(1 << 20)
)

type cliBodyLimitRoundTripper func(*http.Request) (*http.Response, error)

func (f cliBodyLimitRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type cliRepeatedByteReader struct {
	remaining int64
	value     byte
}

func (r *cliRepeatedByteReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	for i := int64(0); i < n; i++ {
		p[i] = r.value
	}
	r.remaining -= n
	return int(n), nil
}

func cliSizedBody(size int64, value byte) io.ReadCloser {
	return io.NopCloser(&cliRepeatedByteReader{remaining: size, value: value})
}

func cliSizedErrorBody(size int64) io.ReadCloser {
	const envelope = `{"error":{"code":"unavailable","message":"bounded error"}}`
	if size < int64(len(envelope)) {
		panic("CLI response-body test size is smaller than its JSON envelope")
	}
	return io.NopCloser(io.MultiReader(
		strings.NewReader(envelope),
		&cliRepeatedByteReader{remaining: size - int64(len(envelope)), value: ' '},
	))
}

func cliBodyLimitClient(status int, body func() io.ReadCloser) *client {
	return &client{
		cfg: Config{BaseURL: "https://probectl.example"},
		hc: &http.Client{Transport: cliBodyLimitRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Header:     make(http.Header),
				Body:       body(),
			}, nil
		})},
	}
}

func TestCLIResponseBodyLimitSuccess(t *testing.T) {
	if maxBufferedResponseBody != expectedCLIResponseBodyLimit {
		t.Fatalf("success response limit = %d, want documented %d", maxBufferedResponseBody, expectedCLIResponseBodyLimit)
	}
	t.Run("exact limit", func(t *testing.T) {
		c := cliBodyLimitClient(http.StatusOK, func() io.ReadCloser {
			return cliSizedBody(expectedCLIResponseBodyLimit, 'x')
		})
		if err := c.do(http.MethodGet, "/v1/tests", nil, nil); err != nil {
			t.Fatalf("exact-limit success response rejected: %v", err)
		}
	})

	t.Run("one byte over", func(t *testing.T) {
		c := cliBodyLimitClient(http.StatusOK, func() io.ReadCloser {
			return cliSizedBody(expectedCLIResponseBodyLimit+1, 'x')
		})
		err := c.do(http.MethodGet, "/v1/tests", nil, nil)
		if !errors.Is(err, httpbody.ErrTooLarge) {
			t.Fatalf("one-past success response error = %v, want ErrTooLarge", err)
		}
	})
}

func TestCLIResponseBodyLimitError(t *testing.T) {
	if maxBufferedErrorResponseBody != expectedCLIErrorResponseBodyLimit {
		t.Fatalf("error response limit = %d, want documented %d", maxBufferedErrorResponseBody, expectedCLIErrorResponseBodyLimit)
	}
	t.Run("exact limit preserves API error", func(t *testing.T) {
		c := cliBodyLimitClient(http.StatusServiceUnavailable, func() io.ReadCloser {
			return cliSizedErrorBody(expectedCLIErrorResponseBodyLimit)
		})
		err := c.do(http.MethodGet, "/v1/tests", nil, nil)
		if err == nil || errors.Is(err, httpbody.ErrTooLarge) || !strings.Contains(err.Error(), "unavailable") {
			t.Fatalf("exact-limit error response = %v, want decoded bounded API error", err)
		}
	})

	t.Run("one byte over", func(t *testing.T) {
		c := cliBodyLimitClient(http.StatusServiceUnavailable, func() io.ReadCloser {
			return cliSizedErrorBody(expectedCLIErrorResponseBodyLimit + 1)
		})
		err := c.do(http.MethodGet, "/v1/tests", nil, nil)
		if !errors.Is(err, httpbody.ErrTooLarge) {
			t.Fatalf("one-past error response error = %v, want ErrTooLarge", err)
		}
	})

	t.Run("stream error is bounded", func(t *testing.T) {
		c := cliBodyLimitClient(http.StatusServiceUnavailable, func() io.ReadCloser {
			return cliSizedErrorBody(expectedCLIErrorResponseBodyLimit + 1)
		})
		err := c.stream(http.MethodGet, "/v1/dashboard-reports/example", nil, io.Discard)
		if !errors.Is(err, httpbody.ErrTooLarge) {
			t.Fatalf("one-past streamed error response = %v, want ErrTooLarge", err)
		}
	})
}
