// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/secrets"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

func runSyncCloudTopology(ctx context.Context, db *store.DB, resolver *secrets.Resolver, log *slog.Logger, args []string) error {
	flags := flag.NewFlagSet("sync-cloud-topology", flag.ContinueOnError)
	tenantArg := flags.String("tenant", "", "tenant UUID that owns the cloud inventory")
	account := flags.String("aws-account", "", "expected AWS account ID")
	region := flags.String("aws-region", "", "AWS region to inventory")
	subscription := flags.String("azure-subscription", "", "Azure subscription UUID to inventory")
	project := flags.String("gcp-project", "", "Google Cloud project ID to inventory")
	credential := flags.String("credential-ref", "", "secrets reference for a read-only cloud identity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	tenantID, err := uuid.Parse(*tenantArg)
	if err != nil || tenantID == uuid.Nil || flags.NArg() != 0 {
		return errors.New("sync-cloud-topology requires an explicit tenant UUID")
	}
	awsSelected := *account != "" && *region != "" && *subscription == "" && *project == ""
	azureSelected := *subscription != "" && *account == "" && *region == "" && *project == ""
	gcpSelected := *project != "" && *account == "" && *region == "" && *subscription == ""
	if !awsSelected && !azureSelected && !gcpSelected {
		return errors.New("sync-cloud-topology requires one source: --aws-account with --aws-region, --azure-subscription, or --gcp-project")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	tenant := tenantID.String()
	status, err := control.NewTenantStatusCache(db.Pool(), 0).TenantStatus(ctx, tenant)
	if err != nil || status != "active" {
		return errors.New("sync-cloud-topology requires an active tenant")
	}
	var inventory topology.CloudInventory
	switch {
	case awsSelected:
		inventory, err = topology.DiscoverAWSCloudInventory(ctx,
			topology.AWSInventoryConfig{Account: *account, Region: *region, CredentialRef: *credential}, resolver)
	case azureSelected:
		inventory, err = topology.DiscoverAzureCloudInventory(ctx,
			topology.AzureInventoryConfig{Subscription: *subscription, CredentialRef: *credential}, resolver)
	default:
		inventory, err = topology.DiscoverGCPCloudInventory(ctx,
			topology.GCPInventoryConfig{Project: *project, CredentialRef: *credential}, resolver)
	}
	if err != nil {
		return err
	}
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if err := (store.CloudTopologyInventories{}).Save(ctx, sc, inventory); err != nil {
			return err
		}
		_, err := audit.TenantAppend(ctx, sc, "deployment:cloud-inventory", "cloud_topology.refresh", inventory.Source.Provider,
			map[string]any{"account": inventory.Source.Account, "location": inventory.Source.Location,
				"resources": len(inventory.Resources), "links": len(inventory.Links)})
		return err
	}); err != nil {
		return err
	}
	log.Info("cloud topology synchronized", "tenant_id", tenant, "provider", inventory.Source.Provider,
		"resources", len(inventory.Resources), "links", len(inventory.Links))
	return nil
}
