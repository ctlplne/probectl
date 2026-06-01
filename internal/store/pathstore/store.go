package pathstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/imfeelingtheagi/netctl/internal/path"
)

// Store persists discovered Paths, tenant-scoped.
type Store interface {
	Save(ctx context.Context, tenantID string, p *path.Path) error
	Close() error
}

// New builds a Store for the given mode. "memory" (or empty) is in-process;
// "clickhouse" writes to a ClickHouse HTTP endpoint at url (e.g.
// http://localhost:8123).
func New(mode, url string) (Store, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "clickhouse":
		if url == "" {
			return nil, errors.New("pathstore: clickhouse mode requires NETCTL_PATHSTORE_URL")
		}
		return NewClickHouse(url)
	default:
		return nil, fmt.Errorf("pathstore: unknown mode %q (want memory|clickhouse)", mode)
	}
}
