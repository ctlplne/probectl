// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/secrets"
)

type AWSInventoryConfig struct {
	Account, Region, CredentialRef string
}

var (
	awsTopologyAccount = regexp.MustCompile(`^[0-9]{12}$`)
	awsTopologyRegion  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]{1,12}){1,3}-[0-9]{1,2}$`)
)

// DiscoverAWSCloudInventory reads a complete topology inventory in an
// explicitly configured account and region. Only STS identity and EC2
// inventory reads are sent. The caller owns tenant association and storage.
func DiscoverAWSCloudInventory(ctx context.Context, cfg AWSInventoryConfig, resolver *secrets.Resolver) (CloudInventory, error) {
	client := cloudInventoryHTTPClient()
	defer client.CloseIdleConnections()
	return discoverAWSCloudInventory(ctx, client, cfg, resolver)
}

func discoverAWSCloudInventory(ctx context.Context, client *http.Client, cfg AWSInventoryConfig, resolver *secrets.Resolver) (CloudInventory, error) {
	if !awsTopologyAccount.MatchString(cfg.Account) || !awsTopologyRegion.MatchString(cfg.Region) || resolver == nil {
		return CloudInventory{}, errors.New("topology: AWS inventory requires an account, region and secrets resolver")
	}
	if _, err := secrets.Parse(cfg.CredentialRef); err != nil {
		return CloudInventory{}, errors.New("topology: AWS inventory requires a credential reference")
	}
	ctx, cancel := context.WithTimeout(ctx, cloudInventoryTimeout)
	defer cancel()
	raw, release, err := resolver.ResolveBytesUncached(ctx, cfg.CredentialRef)
	if err != nil {
		return CloudInventory{}, errors.New("topology: AWS inventory credential could not be resolved")
	}
	auth, err := crypto.DecodeAWSV4Credentials(raw)
	release()
	if err != nil {
		return CloudInventory{}, err
	}
	defer crypto.Zeroize(auth.SecretKey)
	source := awsInventoryClient{http: client, identity: auth, region: cfg.Region}
	var identity struct {
		XMLName xml.Name `xml:"GetCallerIdentityResponse"`
		Account string   `xml:"GetCallerIdentityResult>Account"`
	}
	if err := source.query(ctx, "sts", "GetCallerIdentity", "2011-06-15", nil, &identity); err != nil {
		return CloudInventory{}, err
	}
	if identity.Account != cfg.Account {
		return CloudInventory{}, errors.New("topology: AWS credential account does not match the configured source")
	}
	return readAWSInventory(ctx, source, cfg.Account)
}

type awsInventoryClient struct {
	http     *http.Client
	identity crypto.AWSV4Credentials
	region   string
}

func (c awsInventoryClient) query(ctx context.Context, service, action, version string, params url.Values, dst any) error {
	if params == nil {
		params = make(url.Values)
	}
	params.Set("Action", action)
	params.Set("Version", version)
	encoded := params.Encode()
	u := url.URL{Scheme: "https", Host: crypto.AWSRegionalHost(service, c.region), Path: "/"}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("topology: could not construct AWS %s request", action)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	crypto.SignAWSV4(req, []byte(encoded), c.identity, c.region, service, time.Now(), "content-type")
	body, err := readCloudInventoryResponse(c.http, req)
	if err != nil {
		return fmt.Errorf("topology: AWS %s: %w", action, err)
	}
	if err := xml.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("topology: AWS %s response is invalid", action)
	}
	return nil
}

type awsInventorySet[T any] struct {
	Items []T `xml:"item"`
}

type awsInventoryPage struct {
	XMLName   xml.Name
	NextToken string                               `xml:"nextToken"`
	VPCs      *awsInventorySet[awsInventoryVPC]    `xml:"vpcSet"`
	Subnets   *awsInventorySet[awsInventorySubnet] `xml:"subnetSet"`
	Internet  *awsInventorySet[awsInventoryIGW]    `xml:"internetGatewaySet"`
	NAT       *awsInventorySet[awsInventoryNAT]    `xml:"natGatewaySet"`
	VPN       *awsInventorySet[awsInventoryVPN]    `xml:"vpnGatewaySet"`
	Peerings  *awsInventorySet[awsInventoryPeer]   `xml:"vpcPeeringConnectionSet"`
}

func (c awsInventoryClient) describe(ctx context.Context, action, owner string, paginated bool, appendPage func(awsInventoryPage) int) error {
	params := make(url.Values)
	if paginated {
		params.Set("MaxResults", "100")
	}
	if owner != "" {
		params.Set("Filter.1.Name", "owner-id")
		params.Set("Filter.1.Value.1", owner)
	}
	seen := make(map[string]bool)
	for range cloudInventoryPages {
		var page awsInventoryPage
		if err := c.query(ctx, "ec2", action, "2016-11-15", params, &page); err != nil {
			return err
		}
		if page.XMLName.Local != action+"Response" {
			return fmt.Errorf("topology: AWS %s returned an unexpected response", action)
		}
		if count := appendPage(page); count < 0 || count > MaxCloudInventoryResources {
			return fmt.Errorf("topology: AWS %s omitted its result set or exceeded the inventory budget", action)
		}
		if page.NextToken == "" || page.NextToken == "null" {
			return nil
		}
		if !paginated || len(page.NextToken) > 2048 || seen[page.NextToken] {
			return fmt.Errorf("topology: AWS %s returned invalid pagination", action)
		}
		seen[page.NextToken] = true
		params.Set("NextToken", page.NextToken)
	}
	return fmt.Errorf("topology: AWS %s exceeds the page budget", action)
}

func readAWSInventory(ctx context.Context, c awsInventoryClient, account string) (CloudInventory, error) {
	observedAt := time.Now().UTC()
	var raw awsNetworkInventory
	for _, step := range []struct {
		action, owner string
		paginated     bool
		append        func(awsInventoryPage) int
	}{
		{"DescribeVpcs", account, true, func(p awsInventoryPage) int { return appendAWSInventorySet(&raw.vpcs, p.VPCs) }},
		{"DescribeSubnets", account, true, func(p awsInventoryPage) int { return appendAWSInventorySet(&raw.subnets, p.Subnets) }},
		{"DescribeInternetGateways", account, true, func(p awsInventoryPage) int { return appendAWSInventorySet(&raw.internet, p.Internet) }},
		{"DescribeNatGateways", "", true, func(p awsInventoryPage) int { return appendAWSInventorySet(&raw.nat, p.NAT) }},
		{"DescribeVpnGateways", "", false, func(p awsInventoryPage) int { return appendAWSInventorySet(&raw.vpn, p.VPN) }},
		{"DescribeVpcPeeringConnections", "", true, func(p awsInventoryPage) int { return appendAWSInventorySet(&raw.peers, p.Peerings) }},
	} {
		if err := c.describe(ctx, step.action, step.owner, step.paginated, step.append); err != nil {
			return CloudInventory{}, err
		}
	}
	return raw.normalize(CloudInventorySource{Provider: "aws", Account: account, Location: c.region}, observedAt)
}

func appendAWSInventorySet[T any](dst *[]T, set *awsInventorySet[T]) int {
	if set == nil {
		return -1
	}
	*dst = append(*dst, set.Items...)
	return len(*dst)
}
