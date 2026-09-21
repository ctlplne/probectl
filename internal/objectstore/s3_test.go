// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package objectstore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeS3Transport struct {
	mu      sync.Mutex
	objects map[string][]byte
	headers []http.Header
	status  int
}

func (f *fakeS3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.objects == nil {
		f.objects = map[string][]byte{}
	}
	f.headers = append(f.headers, req.Header.Clone())
	if f.status != 0 {
		return fakeS3Response(f.status, "unavailable", nil), nil
	}
	const bucketPath = "/artifacts/"
	if req.Method == http.MethodGet && req.URL.Query().Get("list-type") == "2" {
		prefix := req.URL.Query().Get("prefix")
		keys := make([]string, 0)
		for key := range f.objects {
			if strings.HasPrefix(key, prefix) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		var body strings.Builder
		body.WriteString("<ListBucketResult><IsTruncated>false</IsTruncated>")
		for _, key := range keys {
			fmt.Fprintf(&body, "<Contents><Key>%s</Key></Contents>", key)
		}
		body.WriteString("</ListBucketResult>")
		return fakeS3Response(http.StatusOK, body.String(), nil), nil
	}
	if !strings.HasPrefix(req.URL.Path, bucketPath) {
		return fakeS3Response(http.StatusBadRequest, "bad bucket", nil), nil
	}
	key := strings.TrimPrefix(req.URL.Path, bucketPath)
	switch req.Method {
	case http.MethodPut:
		body, _ := io.ReadAll(req.Body)
		f.objects[key] = append([]byte(nil), body...)
		return fakeS3Response(http.StatusOK, "", nil), nil
	case http.MethodGet:
		body, ok := f.objects[key]
		if !ok {
			return fakeS3Response(http.StatusNotFound, "", nil), nil
		}
		return fakeS3Response(http.StatusOK, string(body), map[string]string{"Content-Type": "image/png"}), nil
	case http.MethodHead:
		body, ok := f.objects[key]
		if !ok {
			return fakeS3Response(http.StatusNotFound, "", nil), nil
		}
		resp := fakeS3Response(http.StatusOK, "", nil)
		resp.ContentLength = int64(len(body))
		return resp, nil
	case http.MethodDelete:
		delete(f.objects, key)
		return fakeS3Response(http.StatusNoContent, "", nil), nil
	default:
		return fakeS3Response(http.StatusMethodNotAllowed, "", nil), nil
	}
}

func fakeS3Response(status int, body string, headers map[string]string) *http.Response {
	h := make(http.Header)
	for key, value := range headers {
		h.Set(key, value)
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func TestS3StoreTenantIsolationLifecycleAndSigning(t *testing.T) {
	fake := &fakeS3Transport{}
	store, err := newS3(S3Config{
		Endpoint: "https://s3.example", Bucket: "artifacts", Region: "us-east-1",
		AccessKey: "AKID", SecretKey: "secret", SessionToken: "session", Prefix: "probectl",
	}, &http.Client{Transport: fake})
	if err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC) }
	a, _ := ForTenant(store, "tenant-a")
	b, _ := ForTenant(store, "tenant-b")
	ctx := context.Background()
	if err := a.Put(ctx, "browser/a.png", "image/png", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, "browser/b.png", "image/png", []byte("B")); err != nil {
		t.Fatal(err)
	}
	keys, err := a.List(ctx, "browser/")
	if err != nil || len(keys) != 1 || keys[0] != "browser/a.png" {
		t.Fatalf("tenant A list = %v err=%v", keys, err)
	}
	if _, err := a.Get(ctx, "tenant/tenant-b/browser/b.png"); err != ErrNotFound {
		t.Fatalf("tenant A inferred/read tenant B object: %v", err)
	}
	obj, err := b.GetLimited(ctx, "browser/b.png", 1)
	if err != nil || string(obj.Data) != "B" {
		t.Fatalf("tenant B get = %q err=%v", obj.Data, err)
	}
	if _, err := b.GetLimited(ctx, "browser/b.png", 0); err != ErrTooLarge {
		t.Fatalf("bounded get error = %v, want ErrTooLarge", err)
	}
	if n, err := a.DeletePrefix(ctx, "browser/"); err != nil || n != 1 {
		t.Fatalf("tenant A delete = %d err=%v", n, err)
	}
	if obj, err := b.Get(ctx, "browser/b.png"); err != nil || string(obj.Data) != "B" {
		t.Fatalf("tenant A lifecycle affected B: %q err=%v", obj.Data, err)
	}
	for i, header := range fake.headers {
		if !strings.HasPrefix(header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKID/") ||
			header.Get("X-Amz-Content-Sha256") == "" || header.Get("X-Amz-Date") != "20260809T120000Z" ||
			header.Get("X-Amz-Security-Token") != "session" {
			t.Fatalf("request %d is not signed correctly: %v", i, header)
		}
	}
}

func TestS3StoreFailsClosedOnConfigAndOutage(t *testing.T) {
	for _, cfg := range []S3Config{
		{Endpoint: "http://s3.example", Bucket: "b", AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://user:pass@s3.example", Bucket: "b", AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://s3.example", Bucket: "", AccessKey: "a", SecretKey: "s"},
		{Endpoint: "https://s3.example", Bucket: "b", AccessKey: "", SecretKey: "s"},
	} {
		if _, err := newS3(cfg, &http.Client{Transport: &fakeS3Transport{}}); err == nil {
			t.Fatalf("unsafe/incomplete config accepted: %+v", cfg)
		}
	}
	fake := &fakeS3Transport{status: http.StatusServiceUnavailable}
	store, err := newS3(S3Config{Endpoint: "https://s3.example", Bucket: "b", AccessKey: "a", SecretKey: "s"}, &http.Client{Transport: fake})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), "tenant/t/browser/x.png", "image/png", []byte("x")); err == nil {
		t.Fatal("S3 outage must be returned; caller must not publish a partial artifact reference")
	}
}
