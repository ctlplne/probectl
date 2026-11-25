// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package rmm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/secrets"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const maxInventoryConfigBytes = 1 << 20

var inventoryAlias = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type inventoryRoute struct {
	SiteMapping
	Alias         string `json:"inventory_alias"`
	Origin        string `json:"inventory_origin"`
	CredentialRef string `json:"inventory_credential_ref"`
}

type CredentialResolver interface {
	ResolveBytesUncached(context.Context, string) ([]byte, func(), error)
}

// InventorySync contains only deployment-provisioned mappings and opaque
// secret references. A request can name a site alias already owned by the
// authenticated tenant and routing context.
type InventorySync struct {
	routes      map[tenancy.ID]map[string]inventoryRoute
	mappings    *SiteMappings
	credentials CredentialResolver
	writes      license.WriteCapability
	client      *http.Client
}

func NewInventorySync(raw []byte, credentials CredentialResolver, writes license.WriteCapability,
	client *http.Client) (*InventorySync, error) {
	if len(raw) == 0 || len(raw) > maxInventoryConfigBytes || credentials == nil || writes == nil {
		return nil, errors.New("rmm: bounded site configuration, secret resolver and write capability required")
	}
	var routes []inventoryRoute
	if !decodeRMMJSON(raw, &routes) || len(routes) == 0 {
		return nil, errors.New("rmm: expected a JSON array of inventory mappings")
	}
	byTenant := map[tenancy.ID]map[string]inventoryRoute{}
	type account struct {
		vendor Vendor
		id     string
		origin string
	}
	byCredential := map[string]account{}
	var siteRoutes []SiteMapping
	for i, route := range routes {
		if (route.Vendor != NinjaOne && route.Vendor != DattoRMM) || !inventoryAlias.MatchString(route.Alias) ||
			!validHTTPSOrigin(route.Origin) || !secrets.IsRef(route.CredentialRef) {
			return nil, fmt.Errorf("rmm: invalid inventory mapping %d", i+1)
		}
		route.Origin = strings.TrimSuffix(route.Origin, "/")
		if _, err := secrets.Parse(route.CredentialRef); err != nil {
			return nil, fmt.Errorf("rmm: invalid credential reference on inventory mapping %d", i+1)
		}
		key := account{vendor: route.Vendor, id: route.Account, origin: route.Origin}
		if existing, ok := byCredential[route.CredentialRef]; ok && existing != key {
			return nil, fmt.Errorf("rmm: inventory mapping %d reuses a credential reference from a different account", i+1)
		}
		byCredential[route.CredentialRef] = key
		if byTenant[route.TenantID] == nil {
			byTenant[route.TenantID] = map[string]inventoryRoute{}
		}
		if _, duplicate := byTenant[route.TenantID][route.Alias]; duplicate {
			return nil, fmt.Errorf("rmm: duplicate inventory alias on mapping %d", i+1)
		}
		byTenant[route.TenantID][route.Alias] = route
		siteRoutes = append(siteRoutes, route.SiteMapping)
	}
	mappings, err := buildSiteMappings(siteRoutes)
	if err != nil {
		return nil, err
	}
	return &InventorySync{routes: byTenant, mappings: mappings, credentials: credentials,
		writes: writes, client: inventoryClient(client)}, nil
}

// Available reports whether this tenant has a configured site and can still
// publish a review plan. It reads no credentials or vendor data.
func (s *InventorySync) Available(tenantID string) bool {
	return len(s.routes[tenancy.ID(tenantID)]) != 0 && s.writes.Enabled()
}

// Start runs one scoped sync. The control plane has already authorized import
// writes on contextID. Wrong-tenant and wrong-context aliases fail before
// secret resolution. All vendor reads finish before the write transaction.
func (s *InventorySync) Start(ctx context.Context, contextID, alias string, store nmsimport.CaptureStore) (nmsimport.DiscoveryPlan, error) {
	tenant, ok := tenancy.FromContext(ctx)
	route, found := s.routes[tenant][alias]
	if !ok || !found || route.ContextID != contextID {
		return nmsimport.DiscoveryPlan{}, nmsimport.ErrPlanUnavailable
	}
	if !s.writes.Enabled() {
		return nmsimport.DiscoveryPlan{}, license.ErrReadOnly
	}
	source, err := s.source(ctx, route)
	if err != nil {
		return nmsimport.DiscoveryPlan{}, nmsimport.ErrSourceUnavailable
	}
	batch, err := s.mappings.Discover(ctx, source)
	if err != nil {
		return nmsimport.DiscoveryPlan{}, nmsimport.ErrSourceUnavailable
	}
	if !s.writes.Enabled() {
		return nmsimport.DiscoveryPlan{}, license.ErrReadOnly
	}
	return publishSiteInventory(ctx, route.SiteMapping, batch.Devices, store)
}

func (s *InventorySync) source(ctx context.Context, route inventoryRoute) (InventorySource, error) {
	raw, cleanup, err := s.credentials.ResolveBytesUncached(ctx, route.CredentialRef)
	if err != nil {
		return nil, nmsimport.ErrSourceUnavailable
	}
	defer cleanup()
	if len(raw) == 0 || len(raw) > 32<<10 {
		return nil, nmsimport.ErrSourceUnavailable
	}
	switch route.Vendor {
	case NinjaOne:
		bearer, err := ninjaOneMonitoringToken(ctx, s.client, route.Origin, raw)
		if err != nil {
			return nil, err
		}
		return NewNinjaOneInventory(route.Site, route.Origin, bearer, s.client)
	case DattoRMM:
		var lease struct {
			AccessToken string `json:"access_token"`
		}
		if !decodeRMMJSON(raw, &lease) {
			return nil, nmsimport.ErrSourceUnavailable
		}
		return NewDattoInventory(route.Site, route.Origin, lease.AccessToken, s.client)
	default:
		return nil, nmsimport.ErrSourceUnavailable
	}
}

func decodeRMMJSON(raw []byte, dst any) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst) == nil && decoder.Decode(new(json.RawMessage)) == io.EOF
}
