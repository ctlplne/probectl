// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type envelopeRewrapReceipt struct {
	Mode                 string                      `json:"mode"`
	ActiveKeyID          string                      `json:"active_key_id"`
	FromKeyID            string                      `json:"from_key_id,omitempty"`
	VerifyRetiredKeyID   string                      `json:"verify_retired_key_id,omitempty"`
	Stores               []store.EnvelopeRewrapStats `json:"stores"`
	Total                store.EnvelopeRewrapStats   `json:"total"`
	ProviderAuditEventID int64                       `json:"provider_audit_event_id,omitempty"`
}

func runEnvelopeRewrap(ctx context.Context, cfg *config.Config, db *store.DB, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("envelope-rewrap", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "inventory only; do not update sealed values or append an audit event")
	fromKeyID := fs.String("from-key-id", "", "only rewrap values stamped with this retired deployment-envelope key id")
	verifyRetiredKeyID := fs.String("verify-retired-key-id", "", "verify this retired key id has no remaining ciphertext and all other values open")
	jsonOut := fs.Bool("json", false, "emit the no-secret receipt as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if cfg.EnvelopeKeyID == "" {
		return fmt.Errorf("envelope-rewrap: PROBECTL_ENVELOPE_KEY_ID must name the active key")
	}
	mode := "execute"
	verifyOpen := false
	if *dryRun {
		mode = "dry-run"
	}
	if *verifyRetiredKeyID != "" {
		mode = "verify"
		verifyOpen = true
		*dryRun = true
		*fromKeyID = *verifyRetiredKeyID
	}
	if *fromKeyID == cfg.EnvelopeKeyID {
		return fmt.Errorf("envelope-rewrap: from-key-id %q is the active key id", *fromKeyID)
	}

	receipt, err := collectEnvelopeRewrap(ctx, db, cfg.EnvelopeKeyID, *fromKeyID, *dryRun, verifyOpen)
	if err != nil {
		return err
	}
	receipt.Mode = mode
	receipt.ActiveKeyID = cfg.EnvelopeKeyID
	receipt.FromKeyID = *fromKeyID
	receipt.VerifyRetiredKeyID = *verifyRetiredKeyID

	if *verifyRetiredKeyID != "" && receipt.Total.Matched != 0 {
		_ = writeEnvelopeRewrapReceipt(*jsonOut, receipt)
		return fmt.Errorf("envelope-rewrap: retired key id %q still appears in %d sealed value(s)", *verifyRetiredKeyID, receipt.Total.Matched)
	}
	if !*dryRun {
		ev, err := audit.ProviderAppend(ctx, db.Pool(), "system", "envelope.rewrap", "deployment-envelope", map[string]any{
			"active_key_id": cfg.EnvelopeKeyID,
			"from_key_id":   *fromKeyID,
			"stores":        receipt.Stores,
			"total":         receipt.Total,
		})
		if err != nil {
			return fmt.Errorf("envelope-rewrap audit: %w", err)
		}
		receipt.ProviderAuditEventID = ev.Seq
		log.Info("deployment envelope rewrap audited", "seq", ev.Seq, "rewrapped", receipt.Total.Rewrapped)
	}
	return writeEnvelopeRewrapReceipt(*jsonOut, receipt)
}

func collectEnvelopeRewrap(ctx context.Context, db *store.DB, activeKeyID, fromKeyID string, dryRun bool, verifyOpen bool) (envelopeRewrapReceipt, error) {
	var receipt envelopeRewrapReceipt
	tenants, err := store.NewTenants(db.Pool()).List(ctx)
	if err != nil {
		return receipt, err
	}
	alertTotal := store.EnvelopeRewrapStats{Store: "alert_rules.channels"}
	for _, tn := range tenants {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tn.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			stats, err := (store.AlertRules{}).RewrapEnvelopeSecrets(ctx, sc, activeKeyID, fromKeyID, dryRun, verifyOpen)
			if err != nil {
				return err
			}
			alertTotal.Add(stats)
			return nil
		}); err != nil {
			return receipt, err
		}
	}
	receipt.Stores = append(receipt.Stores, alertTotal)
	receipt.Total.Add(alertTotal)

	agentStats, err := enroll.RewrapAgentCA(ctx, db.Pool(), activeKeyID, fromKeyID, dryRun, verifyOpen)
	if err != nil {
		return receipt, err
	}
	receipt.Stores = append(receipt.Stores, agentStats)
	receipt.Total.Add(agentStats)
	return receipt, nil
}

func writeEnvelopeRewrapReceipt(jsonOut bool, receipt envelopeRewrapReceipt) error {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(receipt)
	}
	fmt.Fprintf(os.Stdout, "envelope-rewrap %s: active=%s from=%s values=%d matched=%d rewrapped=%d verified=%d audit_seq=%d\n",
		receipt.Mode, receipt.ActiveKeyID, receipt.FromKeyID, receipt.Total.ValuesScanned,
		receipt.Total.Matched, receipt.Total.Rewrapped, receipt.Total.Verified, receipt.ProviderAuditEventID)
	for _, st := range receipt.Stores {
		fmt.Fprintf(os.Stdout, "  %s: rows=%d values=%d active=%d matched=%d rewrapped=%d verified=%d\n",
			st.Store, st.RowsScanned, st.ValuesScanned, st.Active, st.Matched, st.Rewrapped, st.Verified)
	}
	return nil
}
