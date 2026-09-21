// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package objectstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FSStore is a filesystem-backed Store. Each object is a file under root; its
// content type is kept in a sibling ".meta" file. Suitable for single-node /
// air-gapped deploys; swap for S3/MinIO at scale.
type FSStore struct {
	root string
}

// NewFS returns a filesystem store rooted at dir (created if missing).
func NewFS(dir string) (*FSStore, error) {
	if dir == "" {
		return nil, errors.New("objectstore: empty root dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("objectstore: create root: %w", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	return &FSStore{root: abs}, nil
}

// path resolves key to an absolute path confined to root.
func (s *FSStore) path(key string) (string, error) {
	if err := validKey(key); err != nil {
		return "", err
	}
	p := filepath.Join(s.root, filepath.FromSlash(key))
	// Defense-in-depth: ensure the join stayed under root.
	if p != s.root && !strings.HasPrefix(p, s.root+string(os.PathSeparator)) {
		return "", errors.New("objectstore: key escapes root")
	}
	return p, nil
}

func (s *FSStore) Put(_ context.Context, key, contentType string, data []byte) error {
	p, err := s.path(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return err
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return os.WriteFile(p+".meta", []byte(contentType), 0o600)
}

func (s *FSStore) Get(_ context.Context, key string) (Object, error) {
	p, err := s.path(key)
	if err != nil {
		return Object{}, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return Object{}, ErrNotFound
	}
	if err != nil {
		return Object{}, err
	}
	return Object{Data: data, ContentType: readContentType(p), Size: int64(len(data))}, nil
}

func (s *FSStore) GetLimited(ctx context.Context, key string, maxBytes int64) (Object, error) {
	if maxBytes < 0 || maxBytes == math.MaxInt64 {
		return Object{}, errors.New("objectstore: maxBytes must be non-negative and below MaxInt64")
	}
	p, err := s.path(key)
	if err != nil {
		return Object{}, err
	}
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return Object{}, ErrNotFound
	}
	if err != nil {
		return Object{}, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return Object{}, err
	}
	if int64(len(data)) > maxBytes {
		return Object{}, ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	return Object{Data: data, ContentType: readContentType(p), Size: int64(len(data))}, nil
}

func readContentType(path string) string {
	const maxContentTypeBytes = 1024

	f, err := os.Open(path + ".meta")
	if err != nil {
		return "application/octet-stream"
	}
	defer f.Close()
	meta, err := io.ReadAll(io.LimitReader(f, maxContentTypeBytes+1))
	if err != nil || len(meta) > maxContentTypeBytes {
		return "application/octet-stream"
	}
	if contentType := strings.TrimSpace(string(meta)); contentType != "" {
		return contentType
	}
	return "application/octet-stream"
}

func (s *FSStore) Stat(_ context.Context, key string) (int64, bool, error) {
	p, err := s.path(key)
	if err != nil {
		return 0, false, err
	}
	fi, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return fi.Size(), true, nil
}

// List returns the keys under prefix, sorted (".meta" siblings excluded).
func (s *FSStore) List(ctx context.Context, prefix string) ([]string, error) {
	return s.list(ctx, prefix, -1)
}

// ListLimited returns a context-aware, aggregate-bounded prefix listing.
func (s *FSStore) ListLimited(ctx context.Context, prefix string, maxKeys int) ([]string, error) {
	if maxKeys < 0 {
		return nil, errors.New("objectstore: maxKeys must be non-negative")
	}
	return s.list(ctx, prefix, maxKeys)
}

func (s *FSStore) list(ctx context.Context, prefix string, maxKeys int) ([]string, error) {
	if err := validListPrefix(prefix); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := s.listRoot(prefix)
	if err != nil {
		return nil, err
	}
	var keys []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() || strings.HasSuffix(p, ".meta") {
			return nil
		}
		rel, rerr := filepath.Rel(s.root, p)
		if rerr != nil {
			return rerr
		}
		key := filepath.ToSlash(rel)
		if strings.HasPrefix(key, prefix) {
			if maxKeys >= 0 && len(keys) >= maxKeys {
				return ErrTooMany
			}
			keys = append(keys, key)
		}
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	sort.Strings(keys)
	return keys, err
}

// listRoot confines traversal to the deepest directory implied by prefix.
// "tenant/t1/" walks only that tenant directory; a filename prefix such as
// "worm/.../segment-" walks only its parent directory.
func (s *FSStore) listRoot(prefix string) (string, error) {
	if prefix == "" {
		return s.root, nil
	}
	if strings.HasSuffix(prefix, "/") {
		return s.path(strings.TrimSuffix(prefix, "/"))
	}
	slash := strings.LastIndex(prefix, "/")
	if slash < 0 {
		return s.root, nil
	}
	return s.path(prefix[:slash])
}

// DeletePrefix removes every object under prefix and returns the count
// (S-T5 verifiable deletion). The prefix is validated like any key, so it
// can never escape the root.
func (s *FSStore) DeletePrefix(ctx context.Context, prefix string) (int, error) {
	if prefix == "" {
		return 0, nil
	}
	if err := validKey(strings.TrimSuffix(prefix, "/")); err != nil {
		return 0, err
	}
	keys, err := s.List(ctx, prefix)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, key := range keys {
		path := filepath.Join(s.root, filepath.FromSlash(key))
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return n, fmt.Errorf("objectstore: delete %s: %w", key, err)
		}
		_ = os.Remove(path + ".meta")
		n++
	}
	// Prune now-empty directories under the prefix (best-effort tidiness).
	_ = filepath.WalkDir(filepath.Join(s.root, filepath.FromSlash(strings.TrimSuffix(prefix, "/"))), func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Remove(p) // fails (kept) unless empty
		}
		return nil
	})
	return n, nil
}
