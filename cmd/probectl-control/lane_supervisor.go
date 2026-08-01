// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

var busLaneRefreshInterval = 30 * time.Second

type busLaneSnapshot struct {
	namespaces []string
	tenants    map[string]string
}

func loadBusLaneSnapshot(ctx context.Context) (busLaneSnapshot, error) {
	namespaces, nsErr := tenancy.CurrentRouter().BusNamespaces(ctx)
	tenants, ntErr := tenancy.CurrentRouter().BusNamespaceTenants(ctx)
	if nsErr != nil || ntErr != nil {
		return busLaneSnapshot{}, fmt.Errorf("bus namespace registry unavailable: namespaces=%v tenants=%v", nsErr, ntErr)
	}
	sort.Strings(namespaces)
	return busLaneSnapshot{namespaces: namespaces, tenants: cloneTenantMap(tenants)}, nil
}

func cloneTenantMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (s busLaneSnapshot) key() string {
	var b strings.Builder
	for _, ns := range s.namespaces {
		b.WriteString("ns:")
		b.WriteString(ns)
		b.WriteByte('\n')
	}
	keys := make([]string, 0, len(s.tenants))
	for ns := range s.tenants {
		keys = append(keys, ns)
	}
	sort.Strings(keys)
	for _, ns := range keys {
		b.WriteString("tenant:")
		b.WriteString(ns)
		b.WriteByte('=')
		b.WriteString(s.tenants[ns])
		b.WriteByte('\n')
	}
	return b.String()
}

func superviseBusLaneRestart(
	ctx context.Context,
	name string,
	log *slog.Logger,
	run func(context.Context, busLaneSnapshot) error,
) error {
	const (
		baseBackoff = 1 * time.Second
		maxBackoff  = 30 * time.Second
	)
	backoff := baseBackoff
	snap, err := loadBusLaneSnapshot(ctx)
	if err != nil {
		log.Warn("isolation: bus namespaces unavailable; starting shared lanes only", "subsystem", name, "error", err.Error())
	}

	for {
		err = runBusLaneGeneration(ctx, name, log, snap, run)
		if ctx.Err() != nil {
			return nil
		}
		next, nerr := loadBusLaneSnapshot(ctx)
		if nerr == nil {
			snap = next
		} else {
			log.Warn("isolation: bus namespace refresh failed; retrying current lanes", "subsystem", name, "error", nerr.Error())
		}
		if err == nil {
			backoff = baseBackoff
			continue
		}
		log.Error("supervised lane subsystem failed; restarting after backoff",
			"subsystem", name, "backoff", backoff.String(), "error", err.Error())
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil
		}
		if backoff < maxBackoff {
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

func runBusLaneGeneration(
	ctx context.Context,
	name string,
	log *slog.Logger,
	snap busLaneSnapshot,
	run func(context.Context, busLaneSnapshot) error,
) error {
	genCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runRecovered(genCtx, name, log, func(c context.Context) error {
			return run(c, snap)
		})
	}()

	ticker := time.NewTicker(busLaneRefreshInterval)
	defer ticker.Stop()
	key := snap.key()
	for {
		select {
		case err := <-done:
			return err
		case <-ticker.C:
			next, err := loadBusLaneSnapshot(ctx)
			if err != nil {
				log.Warn("isolation: bus namespace refresh failed; keeping current lane subscriptions",
					"subsystem", name, "error", err.Error())
				continue
			}
			nextKey := next.key()
			if nextKey == key {
				continue
			}
			log.Info("isolation: bus namespace set changed; restarting lane subscriber",
				"subsystem", name, "namespaces", next.namespaces)
			cancel()
			<-done
			return nil
		case <-ctx.Done():
			cancel()
			<-done
			return nil
		}
	}
}
