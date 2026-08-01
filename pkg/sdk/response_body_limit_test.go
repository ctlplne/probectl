// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/httpbody"
)

const (
	expectedSDKResponseBodyLimit      = int64(32 << 20)
	expectedSDKErrorResponseBodyLimit = int64(1 << 20)
)

type sdkBodyLimitRoundTripper func(*http.Request) (*http.Response, error)

func (f sdkBodyLimitRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type sdkRepeatedByteReader struct {
	remaining int64
	value     byte
}

func (r *sdkRepeatedByteReader) Read(p []byte) (int, error) {
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

func sdkSizedBody(size int64, value byte) io.ReadCloser {
	return io.NopCloser(&sdkRepeatedByteReader{remaining: size, value: value})
}

func sdkSizedErrorBody(size int64) io.ReadCloser {
	const envelope = `{"error":{"code":"unavailable","message":"bounded SDK error"}}`
	if size < int64(len(envelope)) {
		panic("SDK response-body test size is smaller than its JSON envelope")
	}
	return io.NopCloser(io.MultiReader(
		strings.NewReader(envelope),
		&sdkRepeatedByteReader{remaining: size - int64(len(envelope)), value: ' '},
	))
}

func sdkBodyLimitClient(status int, body func() io.ReadCloser) *Client {
	return NewClient("https://probectl.example", WithHTTPClient(&http.Client{
		Transport: sdkBodyLimitRoundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Header:     make(http.Header),
				Body:       body(),
			}, nil
		}),
	}))
}

func TestSDKResponseBodyLimitSuccess(t *testing.T) {
	if MaxResponseBodyBytes != expectedSDKResponseBodyLimit {
		t.Fatalf("success response limit = %d, want documented %d", MaxResponseBodyBytes, expectedSDKResponseBodyLimit)
	}
	t.Run("exact limit", func(t *testing.T) {
		c := sdkBodyLimitClient(http.StatusOK, func() io.ReadCloser {
			return sdkSizedBody(expectedSDKResponseBodyLimit, 'x')
		})
		body, err := c.doRaw(context.Background(), http.MethodGet, "/v1/tests", url.Values{}, nil)
		if err != nil {
			t.Fatalf("exact-limit success response rejected: %v", err)
		}
		if len(body) != int(expectedSDKResponseBodyLimit) {
			t.Fatalf("exact-limit response length = %d, want %d", len(body), expectedSDKResponseBodyLimit)
		}
	})

	t.Run("one byte over", func(t *testing.T) {
		c := sdkBodyLimitClient(http.StatusOK, func() io.ReadCloser {
			return sdkSizedBody(expectedSDKResponseBodyLimit+1, 'x')
		})
		_, err := c.doRaw(context.Background(), http.MethodGet, "/v1/tests", url.Values{}, nil)
		if !errors.Is(err, httpbody.ErrTooLarge) {
			t.Fatalf("one-past success response error = %v, want ErrTooLarge", err)
		}
	})
}

func TestSDKResponseBodyLimitError(t *testing.T) {
	if MaxErrorResponseBodyBytes != expectedSDKErrorResponseBodyLimit {
		t.Fatalf("error response limit = %d, want documented %d", MaxErrorResponseBodyBytes, expectedSDKErrorResponseBodyLimit)
	}
	t.Run("exact limit preserves SDK error", func(t *testing.T) {
		c := sdkBodyLimitClient(http.StatusServiceUnavailable, func() io.ReadCloser {
			return sdkSizedErrorBody(expectedSDKErrorResponseBodyLimit)
		})
		_, err := c.doRaw(context.Background(), http.MethodGet, "/v1/tests", url.Values{}, nil)
		var sdkErr *SDKError
		if !errors.As(err, &sdkErr) {
			t.Fatalf("exact-limit error response = %v, want SDKError", err)
		}
		if sdkErr.Code != "unavailable" || sdkErr.Message != "bounded SDK error" ||
			len(sdkErr.Body) != int(expectedSDKErrorResponseBodyLimit) {
			t.Fatalf("decoded exact-limit SDK error = %+v", sdkErr)
		}
	})

	t.Run("one byte over", func(t *testing.T) {
		c := sdkBodyLimitClient(http.StatusServiceUnavailable, func() io.ReadCloser {
			return sdkSizedErrorBody(expectedSDKErrorResponseBodyLimit + 1)
		})
		_, err := c.doRaw(context.Background(), http.MethodGet, "/v1/tests", url.Values{}, nil)
		if !errors.Is(err, ErrResponseBodyTooLarge) {
			t.Fatalf("one-past error response error = %v, want ErrTooLarge", err)
		}
	})
}
