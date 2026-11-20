// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type BGPASPathPublicSource struct {
	Source            string     `json:"source"`
	Collector         string     `json:"collector"`
	BaselineClock     time.Time  `json:"baseline_clock"`
	ArchiveClock      time.Time  `json:"archive_clock"`
	BaselineSHA256    string     `json:"baseline_sha256"`
	ArchiveSHA256     string     `json:"archive_sha256"`
	PeerAddress       netip.Addr `json:"peer_address"`
	PeerASN           uint32     `json:"peer_asn"`
	ArchiveRecord     int64      `json:"archive_record"`
	OperationIndex    int32      `json:"operation_index"`
	ObservedUnixNanos int64      `json:"observed_unix_nanos,string"`
	RIBPeerIndex      *uint16    `json:"rib_peer_index,omitempty"`
	RIBSequence       *uint32    `json:"rib_sequence,omitempty"`
	RIBOriginatedAt   *int64     `json:"rib_originated_unix_nanos,omitempty,string"`
	Coverage          string     `json:"coverage,omitempty"`
}

type BGPASPathPublicSnapshot struct {
	Segments  []bgp.ASPathSegment   `json:"segments"`
	Source    BGPASPathPublicSource `json:"original"`
	AS4Action string                `json:"as4_action"`
}

type BGPASPathPublicEvent struct {
	Route    bgp.RoutePrefix          `json:"route"`
	Kind     string                   `json:"kind"`
	Original BGPASPathPublicSource    `json:"original"`
	Previous *BGPASPathPublicSnapshot `json:"previous,omitempty"`
	Current  *BGPASPathPublicSnapshot `json:"current,omitempty"`
}

// The complete archive parser admits at most four million records per file.
// Reserve separate blocks for a baseline and an update at the same UTC minute.
const bgpASPathArchiveRecordStride = 1 << 24

func validateBGPASPathPublicSource(source BGPASPathPublicSource) error {
	if !bgpVisibilitySourceLabel.MatchString(source.Source) || !bgpVisibilityCollectorLabel.MatchString(source.Collector) ||
		source.BaselineClock.IsZero() || source.ArchiveClock.Before(source.BaselineClock) ||
		source.BaselineClock.Unix() < 0 || source.ArchiveClock.After(time.Unix(0, source.ObservedUnixNanos)) ||
		source.OperationIndex < 0 || source.ObservedUnixNanos <= 0 || source.ArchiveRecord >= bgpASPathArchiveRecordStride-1 {
		return ErrBGPVisibilityInput
	}
	if _, err := bgpVisibilityDigest(source.BaselineSHA256); err != nil {
		return err
	}
	if _, err := bgpVisibilityDigest(source.ArchiveSHA256); err != nil {
		return err
	}
	if source.Coverage != "" {
		if source.ArchiveRecord != 0 || source.OperationIndex != 0 || source.PeerAddress.IsValid() || source.PeerASN != 0 ||
			source.RIBPeerIndex != nil || source.RIBSequence != nil || source.RIBOriginatedAt != nil {
			return ErrBGPVisibilityInput
		}
		switch source.Coverage {
		case "complete_baseline", "archive_gap", "session_change", "path_unavailable":
			return nil
		default:
			return ErrBGPVisibilityInput
		}
	}
	if source.ArchiveRecord < 1 || !source.PeerAddress.IsValid() || source.PeerAddress.Zone() != "" {
		return ErrBGPVisibilityInput
	}
	if source.RIBSequence == nil && source.RIBPeerIndex == nil && source.RIBOriginatedAt == nil {
		return nil
	}
	if source.RIBSequence == nil || source.RIBPeerIndex == nil || source.RIBOriginatedAt == nil ||
		*source.RIBOriginatedAt < 0 || source.ArchiveSHA256 != source.BaselineSHA256 ||
		!source.ArchiveClock.Equal(source.BaselineClock) {
		return ErrBGPVisibilityInput
	}
	return nil
}

func bgpASPathPublicEventValid(event BGPASPathPublicEvent) bool {
	route := event.Route
	if !route.Prefix.IsValid() || route.Prefix != route.Prefix.Masked() || route.Prefix.Addr().Is4In6() ||
		!route.HasPathID && route.PathID != 0 || validateBGPASPathPublicSource(event.Original) != nil {
		return false
	}
	switch event.Kind {
	case "baseline":
		if event.Original.Coverage == "complete_baseline" {
			return event.Previous == nil && event.Current == nil && event.Original.ArchiveClock.Equal(event.Original.BaselineClock) &&
				event.Original.ArchiveSHA256 == event.Original.BaselineSHA256
		}
		return event.Original.RIBSequence != nil && event.Previous == nil && event.Current != nil
	case "coverage_gap":
		return event.Original.Coverage != "" && event.Original.Coverage != "complete_baseline" && event.Previous == nil && event.Current == nil
	case "announcement":
		return event.Original.Coverage == "" && event.Original.RIBSequence == nil && event.Previous == nil && event.Current != nil
	case "withdrawal":
		return event.Original.Coverage == "" && event.Original.RIBSequence == nil && event.Previous != nil && event.Current == nil
	case "path_change":
		return event.Original.Coverage == "" && event.Original.RIBSequence == nil && event.Previous != nil && event.Current != nil
	default:
		return false
	}
}

func bgpASPathArchiveSequence(source BGPASPathPublicSource, kind string) int64 {
	block := 2 * (source.ArchiveClock.Unix() / 60)
	if kind != "baseline" {
		block++
	}
	if kind == "coverage_gap" {
		return (block+1)*bgpASPathArchiveRecordStride - 1
	}
	return block*bgpASPathArchiveRecordStride + source.ArchiveRecord
}

// RecordBGPASPathPublicInScope publishes one already staged original archive
// operation inside the owning monitor's tenant write transaction.
func RecordBGPASPathPublicInScope(ctx context.Context, sc tenancy.Scope, monitor string, event BGPASPathPublicEvent) (bool, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return false, err
	}
	if !bgpVisibilityID(monitor) || !bgpASPathPublicEventValid(event) {
		return false, ErrBGPVisibilityInput
	}
	body, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	key, err := json.Marshal(struct {
		Route    bgp.RoutePrefix
		Kind     string
		Original BGPASPathPublicSource
	}{event.Route, event.Kind, event.Original})
	if err != nil {
		return false, err
	}
	source := event.Original
	peer := source.Source + "/" + source.Collector + "/" + source.PeerAddress.String() + "/" + strconv.FormatUint(uint64(source.PeerASN), 10)
	vantage := hex.EncodeToString(crypto.Hash([]byte(peer)))
	observedAt := time.Unix(0, source.ObservedUnixNanos).UTC()
	digest := crypto.Hash(key)
	tag, err := sc.Q.Exec(ctx, `INSERT INTO bgp_as_path_history
 (tenant_id,monitor_id,source_kind,vantage_key,source_epoch,event_digest,observed_at,event_kind,original,
 previous_path,current_path,has_path_id,path_id,source_sequence,source_operation)
 SELECT monitor.tenant_id,monitor.id,'public_mrt',$4,$5,$6,$7,$8,$9::jsonb->'original',
 $9::jsonb->'previous',$9::jsonb->'current',$10,$11,$12,$13
 FROM bgp_visibility_monitors monitor WHERE monitor.tenant_id=$1 AND monitor.id=$2 AND monitor.prefix=$3::cidr
 ON CONFLICT (tenant_id,monitor_id,source_kind,vantage_key,source_epoch,source_sequence,source_operation,event_digest) DO NOTHING`,
		sc.Tenant.String(), monitor, event.Route.Prefix.String(), vantage, source.BaselineSHA256, digest, observedAt, event.Kind, body,
		event.Route.HasPathID, int64(event.Route.PathID), bgpASPathArchiveSequence(source, event.Kind), source.OperationIndex)
	if err != nil || tag.RowsAffected() == 1 {
		return err == nil, err
	}
	var same bool
	err = sc.Q.QueryRow(ctx, `SELECT (observed_at,event_kind,original,previous_path,current_path) IS NOT DISTINCT FROM
 ($6::timestamptz,$7::text,$8::jsonb->'original',$8::jsonb->'previous',$8::jsonb->'current')
 FROM bgp_as_path_history WHERE tenant_id=$1 AND monitor_id=$2 AND source_kind='public_mrt'
 AND vantage_key=$3 AND source_epoch=$4 AND event_digest=$5`, sc.Tenant.String(), monitor, vantage,
		source.BaselineSHA256, digest, observedAt, event.Kind, body).Scan(&same)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, ErrBGPVisibilityMissing
	}
	if err == nil && !same {
		return false, ErrBGPVisibilityConflict
	}
	return false, err
}
