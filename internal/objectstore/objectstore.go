// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package objectstore is probectl's pluggable blob store for large, out-of-band
// artifacts — starting with S36 browser-synthetic screenshots/waterfalls. It is a
// small Put/Get/Stat interface with a filesystem implementation (the default) and
// an in-memory one (tests); an S3/MinIO implementation slots in behind the same
// interface (PRD §5: object store pluggable). Tenant-owned callers should use a
// TenantStore from ForTenant/ForTenantPrefix, so tenant namespaces are prepended
// by the storage adapter rather than remembered by every handler.
package objectstore

import (
	"context"
	"errors"
	"strings"
)

// ErrNotFound is returned when a key does not exist.
var ErrNotFound = errors.New("objectstore: not found")

// Object is a stored blob plus its content type.
type Object struct {
	Data        []byte
	ContentType string
	Size        int64
}

// Store is a blob store. Implementations must be safe for concurrent use.
type Store interface {
	// Put writes data under key with a content type, overwriting any existing
	// object. The key is a forward-slash path; implementations reject traversal.
	Put(ctx context.Context, key, contentType string, data []byte) error
	// Get returns the object at key, or ErrNotFound.
	Get(ctx context.Context, key string) (Object, error)
	// Stat returns the size and existence of key without reading the body.
	Stat(ctx context.Context, key string) (size int64, exists bool, err error)
	// List returns the keys under a prefix (S-T5 export manifests).
	List(ctx context.Context, prefix string) ([]string, error)
	// DeletePrefix removes every object under a prefix and returns the count
	// (S-T5 verifiable deletion). Deleting an empty prefix is a no-op.
	DeletePrefix(ctx context.Context, prefix string) (int, error)
}

// TenantStore is a tenant-bound view of Store. Callers pass relative artifact
// paths such as "browser/run.png"; the adapter prepends the tenant namespace.
type TenantStore interface {
	Put(ctx context.Context, path, contentType string, data []byte) error
	Get(ctx context.Context, path string) (Object, error)
	Stat(ctx context.Context, path string) (size int64, exists bool, err error)
	List(ctx context.Context, prefix string) ([]string, error)
	DeletePrefix(ctx context.Context, prefix string) (int, error)
	Key(path string) string
}

type tenantStore struct {
	store Store
	root  string
}

// ForTenant binds store to the standard pooled tenant namespace:
// "tenant/<tenantID>/".
func ForTenant(store Store, tenantID string) (TenantStore, error) {
	return ForTenantPrefix(store, "", tenantID)
}

// ForTenantPrefix binds store to an isolation-routed object namespace. Empty
// prefix falls back to the pooled "tenant/<tenantID>/" root. Non-empty prefixes
// are resolved by the deployment router (for example "silo/<tenantID>").
func ForTenantPrefix(store Store, prefix, tenantID string) (TenantStore, error) {
	if store == nil {
		return nil, errors.New("objectstore: nil store")
	}
	if err := validTenantID(tenantID); err != nil {
		return nil, err
	}
	root := strings.Trim(prefix, "/")
	if root == "" {
		root = TenantKey(tenantID)
	}
	if err := validKey(root); err != nil {
		return nil, err
	}
	return tenantStore{store: store, root: root}, nil
}

func validTenantID(tenantID string) error {
	if tenantID == "" {
		return errors.New("objectstore: empty tenant id")
	}
	if strings.ContainsAny(tenantID, "/\\\x00") || tenantID == "." || tenantID == ".." {
		return errors.New("objectstore: invalid tenant id")
	}
	return nil
}

func validRelative(path string, allowEmpty bool) error {
	if path == "" {
		if allowEmpty {
			return nil
		}
		return errors.New("objectstore: empty relative path")
	}
	return validKey(path)
}

func (t tenantStore) fullKey(path string, allowEmpty bool) (string, error) {
	if err := validRelative(path, allowEmpty); err != nil {
		return "", err
	}
	if path == "" {
		return t.root + "/", nil
	}
	return t.root + "/" + strings.TrimPrefix(path, "/"), nil
}

func (t tenantStore) Put(ctx context.Context, path, contentType string, data []byte) error {
	key, err := t.fullKey(path, false)
	if err != nil {
		return err
	}
	return t.store.Put(ctx, key, contentType, data)
}

func (t tenantStore) Get(ctx context.Context, path string) (Object, error) {
	key, err := t.fullKey(path, false)
	if err != nil {
		return Object{}, err
	}
	return t.store.Get(ctx, key)
}

func (t tenantStore) Stat(ctx context.Context, path string) (int64, bool, error) {
	key, err := t.fullKey(path, false)
	if err != nil {
		return 0, false, err
	}
	return t.store.Stat(ctx, key)
}

func (t tenantStore) List(ctx context.Context, prefix string) ([]string, error) {
	keyPrefix, err := t.fullKey(prefix, true)
	if err != nil {
		return nil, err
	}
	keys, err := t.store.List(ctx, keyPrefix)
	if err != nil {
		return nil, err
	}
	rootPrefix := t.root + "/"
	rel := keys[:0]
	for _, key := range keys {
		if strings.HasPrefix(key, rootPrefix) {
			rel = append(rel, strings.TrimPrefix(key, rootPrefix))
		}
	}
	return rel, nil
}

func (t tenantStore) DeletePrefix(ctx context.Context, prefix string) (int, error) {
	keyPrefix, err := t.fullKey(prefix, true)
	if err != nil {
		return 0, err
	}
	return t.store.DeletePrefix(ctx, keyPrefix)
}

func (t tenantStore) Key(path string) string {
	key, err := t.fullKey(path, false)
	if err != nil {
		return ""
	}
	return key
}

// validKey rejects empty keys, absolute paths, and any traversal so a tenant
// prefix can't be escaped (defense-in-depth alongside the caller's prefixing).
func validKey(key string) error {
	if key == "" {
		return errors.New("objectstore: empty key")
	}
	if strings.HasPrefix(key, "/") || strings.HasPrefix(key, "\\") {
		return errors.New("objectstore: key must be relative")
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == ".." {
			return errors.New("objectstore: key must not contain \"..\"")
		}
	}
	if strings.Contains(key, "\x00") {
		return errors.New("objectstore: key must not contain NUL")
	}
	return nil
}

// TenantKey builds a tenant-namespaced key: "tenant/<tenantID>/<parts...>". The
// tenant prefix is what keeps one tenant's artifacts isolated from another's.
func TenantKey(tenantID string, parts ...string) string {
	return strings.Join(append([]string{"tenant", tenantID}, parts...), "/")
}

// PrefixedKey builds a key under an isolation-routed prefix (S-T2 siloed
// object namespace). An empty prefix falls back to the standard TenantKey
// layout, so pooled callers behave exactly as before.
func PrefixedKey(prefix, tenantID string, parts ...string) string {
	if prefix == "" {
		return TenantKey(tenantID, parts...)
	}
	return strings.Join(append([]string{strings.Trim(prefix, "/")}, parts...), "/")
}
