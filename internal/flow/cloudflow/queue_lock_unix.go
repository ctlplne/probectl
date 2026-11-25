// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package cloudflow

import (
	"errors"
	"fmt"
	"math"
	"os"

	"golang.org/x/sys/unix"
)

func lockQueueCheckpoint(file *os.File) error {
	fd := file.Fd()
	if fd > math.MaxInt {
		return errors.New("cloudflow: invalid queue checkpoint file descriptor")
	}
	err := unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return errors.New("cloudflow: another collector is polling this tenant's queue")
	}
	if err != nil {
		return fmt.Errorf("cloudflow: acquire queue checkpoint lock: %w", err)
	}
	return nil
}
