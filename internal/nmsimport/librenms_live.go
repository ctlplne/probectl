// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"encoding/json"
	"io"
	"sort"
)

// CaptureConfiguredLibreNMSInventory reads all five documented resource
// shapes under one tenant/source-bound plan. A first bounded group-list pass
// establishes exact ID/name pairs; the capture pass must see the same pairs
// before membership URLs are opened. No endpoint receives a URL or group name
// from a caller or response body outside that captured list. The result is
// sealed and inert: review/action assignment is a separate authorized step.
func (s CaptureStore) CaptureConfiguredLibreNMSInventory(ctx context.Context,
	contextID, planID string, policy LibreNMSFetchPolicy) (string, error) {
	groupBody, err := s.OpenConfiguredLibreNMS(ctx, contextID, planID, "groups", policy)
	if err != nil {
		return "", err
	}
	groupNames := make(map[string]string)
	seenNames := make(map[string]bool)
	err = streamLibreNMSLiveGroups(groupBody, func(snapshot Snapshot) error {
		for _, row := range snapshot.Rows {
			if _, duplicate := groupNames[row.ExternalID]; duplicate || seenNames[row.Label] {
				return ErrInvalidPage
			}
			groupNames[row.ExternalID] = row.Label
			seenNames[row.Label] = true
		}
		return nil
	})
	groupBody.Close()
	if err != nil {
		return "", ErrInvalidPage
	}
	var readers []*deferredLibreNMSReader
	defer func() {
		for _, reader := range readers {
			reader.Close()
		}
	}()
	newReader := func(resource, groupID string) *deferredLibreNMSReader {
		reader := &deferredLibreNMSReader{open: func() (io.ReadCloser, error) {
			if resource == "membership" {
				return s.OpenConfiguredLibreNMSMembership(ctx, contextID, planID, groupID, policy)
			}
			return s.OpenConfiguredLibreNMS(ctx, contextID, planID, resource, policy)
		}}
		readers = append(readers, reader)
		return reader
	}
	devices := newReader("devices", "")
	locations := newReader("locations", "")
	groups := newReader("groups", "")
	rules := newReader("rules", "")
	ids := make([]string, 0, len(groupNames))
	for id := range groupNames {
		ids = append(ids, id)
	}
	sort.Strings(ids) // stable page ordinals for exact retry
	memberships := make([]LibreNMSMembershipList, 0, len(ids))
	for _, id := range ids {
		memberships = append(memberships, LibreNMSMembershipList{
			GroupID: id, GroupName: groupNames[id], Raw: newReader("membership", id),
		})
	}
	return s.captureLibreNMSInventory(ctx, contextID, planID,
		devices, locations, groups, rules, memberships, func() error {
			return s.verifyConfiguredLibreNMSInventory(ctx, contextID, planID, policy, ids)
		})
}

func streamLibreNMSLiveGroups(raw io.Reader, emit func(Snapshot) error) error {
	return streamLibreNMSList(raw, "groups", true,
		func(value json.RawMessage) (Row, error) {
			var group libreNMSGroup
			if json.Unmarshal(value, &group) != nil || !validMembershipName(group.Name) {
				return Row{}, ErrInvalidPage
			}
			return libreNMSGroupRow(group)
		}, emit)
}

// A source response is opened only when the decoder asks for its first byte.
// This keeps each network read after the plan's tenant-first lookup and avoids
// pre-opening responses whose group IDs have not been captured yet.
type deferredLibreNMSReader struct {
	open   func() (io.ReadCloser, error)
	body   io.ReadCloser
	opened bool
}

func (r *deferredLibreNMSReader) Read(p []byte) (int, error) {
	if !r.opened {
		r.opened = true
		var err error
		r.body, err = r.open()
		if err != nil {
			return 0, err
		}
	}
	if r.body == nil {
		return 0, io.EOF
	}
	n, err := r.body.Read(p)
	if err != nil {
		r.Close()
	}
	return n, err
}

func (r *deferredLibreNMSReader) Close() error {
	r.opened = true
	if r.body == nil {
		return nil
	}
	err := r.body.Close()
	r.body = nil
	return err
}
