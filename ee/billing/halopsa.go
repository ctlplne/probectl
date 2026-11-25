// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package billing

import (
	"context"
	"errors"
	"math"
	"strconv"

	"github.com/ctlplne/probectl/internal/notify"
)

// PSAQuantities is a single tenant's billing snapshot.
type PSAQuantities struct {
	Devices int64
	Agents  int64
}

// HaloSubscriptions binds a tenant's inventory to two preconfigured billing
// subscriptions under the same Halo customer.
type HaloSubscriptions struct {
	CustomerID          int32 `json:"customer_id"`
	DevicesSubscription int32 `json:"devices_subscription_id"`
	AgentsSubscription  int32 `json:"agents_subscription_id"`
}

type HaloBillingWriter struct {
	tenant        string
	api           *notify.HaloAPI
	subscriptions HaloSubscriptions
}

func NewHaloBillingWriter(tenant, origin string, credentials notify.HaloCredentials, subscriptions HaloSubscriptions, client notify.Doer) (*HaloBillingWriter, error) {
	if tenant == "" || subscriptions.CustomerID <= 0 || subscriptions.DevicesSubscription <= 0 ||
		subscriptions.AgentsSubscription <= 0 || subscriptions.DevicesSubscription == subscriptions.AgentsSubscription {
		return nil, errors.New("billing: Halo requires a tenant, a customer and two distinct subscriptions")
	}
	api, err := notify.NewHaloAPI(origin, credentials, client)
	if err != nil {
		return nil, err
	}
	return &HaloBillingWriter{tenant: tenant, api: api, subscriptions: subscriptions}, nil
}

// Halo's usage billing contract represents subscriptions as SoftwareLicence
// records with type 1 and an absolute count.
const haloUsageSubscription = 1

type haloSubscription struct {
	ID       int32  `json:"id"`
	Customer int32  `json:"client_id"`
	Type     int    `json:"type"`
	Count    *int64 `json:"count"`
}

type haloQuantityWrite struct {
	ID    int32 `json:"id"`
	Count int64 `json:"count"`
}

func (c *HaloBillingWriter) read(ctx context.Context, id int32) (int64, error) {
	var row haloSubscription
	if err := c.api.Get(ctx, &row, nil, "SoftwareLicence", strconv.FormatInt(int64(id), 10)); err != nil {
		return 0, err
	}
	if row.ID != id || row.Customer != c.subscriptions.CustomerID || row.Type != haloUsageSubscription ||
		row.Count == nil || *row.Count < 0 || *row.Count > math.MaxInt32 {
		return 0, errors.New("billing: Halo subscription did not match the configured customer and usage type")
	}
	return *row.Count, nil
}

// Sync reads both owned subscriptions before sending a count-only update.
// Absolute values make a retry safe if the remote side applied one or both
// updates before the client received an error.
func (c *HaloBillingWriter) Sync(ctx context.Context, tenant string, counts PSAQuantities) (bool, error) {
	return c.sync(ctx, tenant, counts, nil)
}

func (c *HaloBillingWriter) sync(ctx context.Context, tenant string, counts PSAQuantities, beforeWrite func() error) (bool, error) {
	desired, updates, err := c.quantityChanges(ctx, tenant, counts)
	if err != nil || len(updates) == 0 {
		return false, err
	}
	if beforeWrite != nil {
		if err := beforeWrite(); err != nil {
			return false, err
		}
	}
	if _, err := c.api.Post(ctx, updates, "SoftwareLicence"); err != nil {
		return false, err
	}
	for _, line := range desired {
		current, err := c.read(ctx, line.ID)
		if err != nil {
			return false, err
		}
		if current != line.Count {
			return false, errors.New("billing: Halo did not confirm the requested quantity")
		}
	}
	return true, nil
}

func (c *HaloBillingWriter) quantityChanges(ctx context.Context, tenant string, counts PSAQuantities) (desired, updates []haloQuantityWrite, err error) {
	if tenant != c.tenant {
		return nil, nil, errors.New("billing: Halo billing writer is bound to another tenant")
	}
	if counts.Devices < 0 || counts.Devices > math.MaxInt32 || counts.Agents < 0 || counts.Agents > math.MaxInt32 {
		return nil, nil, errors.New("billing: quantities exceed the vendor's supported range")
	}
	desired = []haloQuantityWrite{
		{ID: c.subscriptions.DevicesSubscription, Count: counts.Devices},
		{ID: c.subscriptions.AgentsSubscription, Count: counts.Agents},
	}
	for _, line := range desired {
		current, err := c.read(ctx, line.ID)
		if err != nil {
			return nil, nil, err
		}
		if current != line.Count {
			updates = append(updates, line)
		}
	}
	return desired, updates, nil
}
