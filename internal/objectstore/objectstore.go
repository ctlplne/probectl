// Package objectstore is probectl's pluggable blob store for large, out-of-band
// artifacts — starting with S36 browser-synthetic screenshots/waterfalls. It is a
// small Put/Get/Stat interface with a filesystem implementation (the default) and
// an in-memory one (tests); an S3/MinIO implementation slots in behind the same
// interface (PRD §5: object store pluggable). Keys are caller-namespaced by
// tenant (e.g. "tenant/<id>/browser/<run>.png"), so artifacts are tenant-isolated
// at the storage layer (F50).
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
