// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
)

const (
	queueCheckpointLimit = 65536
	queueCheckpointTTL   = 32 * 24 * time.Hour
	queueLockName        = ".poll.lock"
)

type queueCheckpoint struct {
	root  *os.Root
	lock  *os.File
	count int
}

// openQueueCheckpoint uses a distinct directory per tenant and queue/object
// scope even when operators intentionally share a private volume. Markers
// contain no credentials or object names. A lost marker causes a replay.
func openQueueCheckpoint(ctx context.Context, q flow.CloudQueueConfig, tenant, provider string, now time.Time) (*queueCheckpoint, error) {
	parent, err := os.OpenRoot(q.StateDir)
	if err != nil {
		return nil, fmt.Errorf("cloudflow: open queue state directory: %w", err)
	}
	defer parent.Close()
	if info, err := parent.Stat("."); err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("cloudflow: queue state directory must be private to the collector account")
	}
	name := "queue-" + checkpointDigest(tenant, provider, q.Project, q.Subscription, q.Account, q.Region, q.Name,
		q.Object.Account, q.Object.Region, q.Object.ExpectedOwner, q.Object.Bucket, q.Prefix)
	if err := parent.Mkdir(name, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	info, err := parent.Lstat(name)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("cloudflow: queue checkpoint scope must be a private directory")
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	c := &queueCheckpoint{root: root}
	if err := c.acquire(); err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := c.expire(ctx, now.Add(-queueCheckpointTTL)); err != nil {
		_ = c.close()
		return nil, err
	}
	return c, nil
}

func (c *queueCheckpoint) acquire() error {
	lock, err := c.root.OpenFile(queueLockName, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	info, err := c.root.Lstat(queueLockName)
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		_ = lock.Close()
		return errors.New("cloudflow: invalid queue checkpoint lock")
	}
	if err := lockQueueCheckpoint(lock); err != nil {
		_ = lock.Close()
		return err
	}
	c.lock = lock
	return nil
}

func (c *queueCheckpoint) close() error {
	return errors.Join(c.root.Close(), c.lock.Close())
}

func checkpointDigest(values ...string) string {
	encoded, _ := json.Marshal(values) // A slice of strings always marshals.
	return hex.EncodeToString(crypto.Hash(encoded))
}

func (c *queueCheckpoint) expire(ctx context.Context, before time.Time) error {
	dir, err := c.root.Open(".")
	if err != nil {
		return err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(queueCheckpointLimit + 2)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) > queueCheckpointLimit+1 {
		return errors.New("cloudflow: queue checkpoint exceeds the entry budget")
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if e.Name() == queueLockName {
			continue
		}
		encoded, ok := strings.CutSuffix(e.Name(), ".done")
		if _, err := hex.DecodeString(encoded); !ok || len(encoded) != 64 || err != nil {
			return errors.New("cloudflow: unexpected file within queue checkpoint scope")
		}
		info, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
			return errors.New("cloudflow: invalid entry within queue checkpoint scope")
		}
		if info.ModTime().Before(before) {
			if err := c.root.Remove(e.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			continue
		}
		c.count++
	}
	return nil
}

func (c *queueCheckpoint) contains(mark string) (bool, error) {
	info, err := c.root.Lstat(mark)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
		return false, errors.New("cloudflow: invalid queue checkpoint marker")
	}
	return true, nil
}

func (c *queueCheckpoint) remember(mark string) error {
	f, err := c.root.OpenFile(mark, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, fs.ErrExist) {
		_, err = c.contains(mark)
		return err
	}
	if err != nil {
		return err
	}
	c.count++
	syncErr := f.Sync()
	return errors.Join(syncErr, f.Close())
}
