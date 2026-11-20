// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

type PublicMRTReceipt struct {
	Source       string    `json:"source"`
	Collector    string    `json:"collector"`
	Kind         string    `json:"kind"`
	ArchiveClock time.Time `json:"archive_clock"`
	FetchedAt    time.Time `json:"fetched_at"`
	URL          string    `json:"url"`
	Compression  string    `json:"compression"`
	Attribution  string    `json:"attribution"`
	Bytes        int64     `json:"bytes"`
	SHA256       string    `json:"sha256"`
}

// PublicMRTCache is a deployment-wide cache with one explicitly enabled fetch
// process. Each original archive is reusable across every local prefix and
// tenant. Serving code can only use Open, which has no network access.
type PublicMRTCache struct {
	directory string
	maxBytes  int64
	client    Doer
	writer    sync.Mutex
}

func NewPublicMRTCache(directory string, maxBytes int64, client Doer) (*PublicMRTCache, error) {
	if !filepath.IsAbs(directory) || maxBytes < 1 || maxBytes > 4<<30 {
		return nil, ErrPublicMRTArchive
	}
	return &PublicMRTCache{directory: directory, maxBytes: maxBytes, client: client}, nil
}

func (cache *PublicMRTCache) Fetch(ctx context.Context, ref PublicMRTArchiveRef) (PublicMRTReceipt, error) {
	request, err := PublicMRTRequest(ref)
	if err != nil {
		return PublicMRTReceipt{}, err
	}
	cache.writer.Lock()
	defer cache.writer.Unlock()
	if err := ctx.Err(); err != nil {
		return PublicMRTReceipt{}, err
	}
	path := cache.path(request)
	if _, err := os.Lstat(path); err == nil {
		receipt, file, err := cache.open(ctx, request)
		if err == nil {
			err = file.Close()
		}
		return receipt, err
	} else if !errors.Is(err, os.ErrNotExist) {
		return PublicMRTReceipt{}, err
	}
	if err := os.MkdirAll(cache.directory, 0o700); err != nil {
		return PublicMRTReceipt{}, err
	}
	return cache.fetch(ctx, request, path)
}

func (cache *PublicMRTCache) fetch(ctx context.Context, request PublicMRTArchiveRequest, path string) (PublicMRTReceipt, error) {
	body, expected, err := openPublicMRTArchive(ctx, request, cache.maxBytes, cache.client)
	if err != nil {
		return PublicMRTReceipt{}, err
	}
	defer body.Close()
	stage, err := os.MkdirTemp(cache.directory, ".public-mrt-")
	if err != nil {
		return PublicMRTReceipt{}, err
	}
	defer os.RemoveAll(stage)
	receipt := publicMRTReceipt(request)
	receipt.FetchedAt = time.Now().UTC()
	receipt.Bytes = expected
	receipt.SHA256, err = stagePublicMRT(ctx, stage, body, expected)
	if err != nil {
		return PublicMRTReceipt{}, err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return PublicMRTReceipt{}, err
	}
	if err := os.WriteFile(filepath.Join(stage, "receipt.json"), raw, 0o400); err != nil {
		return PublicMRTReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return PublicMRTReceipt{}, err
	}
	if err := os.Rename(stage, path); err != nil {
		return PublicMRTReceipt{}, err
	}
	return receipt, nil
}

func stagePublicMRT(ctx context.Context, path string, body io.Reader, expected int64) (string, error) {
	file, err := os.OpenFile(filepath.Join(path, "original"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if err != nil {
		return "", err
	}
	defer file.Close()
	limited := &io.LimitedReader{R: publicMRTContextReader{ctx: ctx, source: body}, N: expected + 1}
	digest, err := crypto.HashReader(io.TeeReader(limited, file))
	if err != nil || limited.N != 1 {
		return "", errors.Join(ErrPublicMRTArchive, err)
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest), nil
}

func (cache *PublicMRTCache) Open(ctx context.Context, ref PublicMRTArchiveRef) (PublicMRTReceipt, *os.File, error) {
	request, err := PublicMRTRequest(ref)
	if err != nil {
		return PublicMRTReceipt{}, nil, err
	}
	return cache.open(ctx, request)
}

func (cache *PublicMRTCache) open(ctx context.Context, request PublicMRTArchiveRequest) (PublicMRTReceipt, *os.File, error) {
	path := cache.path(request)
	receipt, err := readPublicMRTReceipt(path, request, cache.maxBytes)
	if err != nil {
		return PublicMRTReceipt{}, nil, err
	}
	file, err := os.Open(filepath.Join(path, "original"))
	if err != nil {
		return PublicMRTReceipt{}, nil, err
	}
	if err := verifyPublicMRTFile(ctx, file, receipt); err != nil {
		file.Close()
		return PublicMRTReceipt{}, nil, err
	}
	return receipt, file, nil
}

func readPublicMRTReceipt(path string, request PublicMRTArchiveRequest, maxBytes int64) (PublicMRTReceipt, error) {
	file, err := os.Open(filepath.Join(path, "receipt.json"))
	if err != nil {
		return PublicMRTReceipt{}, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		return PublicMRTReceipt{}, errors.Join(ErrPublicMRTArchive, err)
	}
	var receipt PublicMRTReceipt
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return PublicMRTReceipt{}, ErrPublicMRTArchive
	}
	identity := receipt
	identity.FetchedAt, identity.Bytes, identity.SHA256 = time.Time{}, 0, ""
	if identity != publicMRTReceipt(request) || receipt.FetchedAt.IsZero() ||
		receipt.Bytes < 1 || receipt.Bytes > maxBytes || len(receipt.SHA256) != 64 {
		return PublicMRTReceipt{}, ErrPublicMRTArchive
	}
	return receipt, nil
}

func verifyPublicMRTFile(ctx context.Context, file *os.File, receipt PublicMRTReceipt) error {
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != receipt.Bytes {
		return errors.Join(ErrPublicMRTArchive, err)
	}
	bounded := &io.LimitedReader{R: publicMRTContextReader{ctx: ctx, source: file}, N: receipt.Bytes + 1}
	digest, err := crypto.HashReader(bounded)
	if err != nil || bounded.N != 1 || hex.EncodeToString(digest) != receipt.SHA256 {
		return errors.Join(ErrPublicMRTArchive, err)
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}

func publicMRTReceipt(request PublicMRTArchiveRequest) PublicMRTReceipt {
	return PublicMRTReceipt{Source: request.Ref.Source, Collector: request.Ref.Collector,
		Kind: string(request.Ref.Kind), ArchiveClock: request.Ref.At, URL: request.URL,
		Compression: request.Compression, Attribution: request.Attribution}
}

func (cache *PublicMRTCache) path(request PublicMRTArchiveRequest) string {
	ref := request.Ref
	return filepath.Join(cache.directory, ref.Source+"-"+ref.Collector+"-"+string(ref.Kind)+"-"+ref.At.Format("20060102T1504Z"))
}

type publicMRTContextReader struct {
	ctx    context.Context
	source io.Reader
}

func (reader publicMRTContextReader) Read(dst []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.source.Read(dst)
}
