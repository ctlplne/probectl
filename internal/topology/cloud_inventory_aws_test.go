// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/secrets"
)

type cloudInventoryHTTPFixture func(*http.Request) (*http.Response, error)

func (f cloudInventoryHTTPFixture) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestAWSCloudInventoryVerifiesAccountAndFollowsScopedPagination(t *testing.T) {
	const owner = "111122223333"
	resolver, err := secrets.NewResolver(time.Minute, secrets.NewEnvSource(func(name string) string {
		if name == "CLOUD_INVENTORY_READER" {
			return `{"access_key_id":"FIXTUREACCESS0001","secret_access_key":"fixture-topology-material","session_token":"fixture-topology-session"}`
		}
		return ""
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(resolver.Close)

	config := AWSInventoryConfig{Account: owner, Region: "eu-west-1", CredentialRef: "env:CLOUD_INVENTORY_READER"}
	ownerXML := owner
	requestCount := 0
	failNAT := false
	missingNATSet := false
	client := &http.Client{Transport: cloudInventoryHTTPFixture(func(req *http.Request) (*http.Response, error) {
		requestCount++
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		params, err := url.ParseQuery(string(raw))
		if err != nil || req.Method != http.MethodPost || req.URL.Scheme != "https" || req.URL.Path != "/" || req.URL.RawQuery != "" ||
			req.Header.Get("X-Amz-Security-Token") != "fixture-topology-session" {
			return nil, fmt.Errorf("unscoped inventory request")
		}
		action := params.Get("Action")
		service := "ec2"
		if action == "GetCallerIdentity" {
			service = "sts"
		}
		if req.URL.Host != service+".eu-west-1.amazonaws.com" ||
			!strings.Contains(req.Header.Get("Authorization"), "/eu-west-1/"+service+"/aws4_request,") {
			return nil, fmt.Errorf("signature left the pinned AWS service")
		}
		if action == "DescribeVpcs" || action == "DescribeSubnets" || action == "DescribeInternetGateways" {
			if params.Get("Filter.1.Name") != "owner-id" || params.Get("Filter.1.Value.1") != owner {
				return nil, fmt.Errorf("ownership filter missing")
			}
		}
		var data string
		switch action {
		case "GetCallerIdentity":
			data = "<GetCallerIdentityResult><Account>" + ownerXML + "</Account></GetCallerIdentityResult>"
		case "DescribeVpcs":
			if params.Get("NextToken") == "fixture-page/+" {
				data = `<vpcSet><item><vpcId>vpc-22222222</vpcId><ownerId>111122223333</ownerId><cidrBlock>10.0.0.0/16</cidrBlock></item></vpcSet><nextToken>null</nextToken>`
			} else if params.Get("NextToken") == "" {
				data = `<vpcSet><item><vpcId>vpc-11111111</vpcId><ownerId>111122223333</ownerId><cidrBlock>10.0.0.0/16</cidrBlock>
				<ipv6CidrBlockAssociationSet><item><ipv6CidrBlock>2001:db8::/48</ipv6CidrBlock></item></ipv6CidrBlockAssociationSet></item>
				<item><vpcId>vpc-33333333</vpcId><ownerId>999988887777</ownerId><cidrBlock>10.0.0.0/16</cidrBlock></item></vpcSet><nextToken>fixture-page/+</nextToken>`
			}
		case "DescribeSubnets":
			data = `<subnetSet><item><subnetId>subnet-10101010</subnetId><vpcId>vpc-11111111</vpcId><ownerId>111122223333</ownerId><cidrBlock>10.0.1.0/24</cidrBlock></item></subnetSet>`
		case "DescribeInternetGateways":
			data = `<internetGatewaySet><item><internetGatewayId>igw-11221122</internetGatewayId><ownerId>111122223333</ownerId><attachmentSet>
			<item><vpcId>vpc-11111111</vpcId><state>available</state></item></attachmentSet></item></internetGatewaySet>`
		case "DescribeNatGateways":
			if failNAT {
				return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("temporary failure"))}, nil
			}
			data = `<natGatewaySet><item><natGatewayId>nat-22222222</natGatewayId><vpcId>vpc-11111111</vpcId><subnetId>subnet-10101010</subnetId><state>available</state></item></natGatewaySet>`
			if missingNATSet {
				data = `<requestId>fixture-incomplete-response</requestId>`
			}
		case "DescribeVpnGateways":
			data = `<vpnGatewaySet><item><vpnGatewayId>vgw-22222222</vpnGatewayId><state>available</state><attachments><item><vpcId>vpc-22222222</vpcId><state>attached</state></item></attachments></item></vpnGatewaySet>`
		case "DescribeVpcPeeringConnections":
			data = `<vpcPeeringConnectionSet>
			<item><vpcPeeringConnectionId>pcx-11111111</vpcPeeringConnectionId><status><code>active</code></status>
			<requesterVpcInfo><vpcId>vpc-11111111</vpcId><ownerId>111122223333</ownerId></requesterVpcInfo>
			<accepterVpcInfo><vpcId>vpc-22222222</vpcId><ownerId>111122223333</ownerId><region>eu-west-1</region></accepterVpcInfo></item>
			<item><vpcPeeringConnectionId>pcx-22222222</vpcPeeringConnectionId><status><code>active</code></status>
			<requesterVpcInfo><vpcId>vpc-22222222</vpcId><ownerId>111122223333</ownerId></requesterVpcInfo>
			<accepterVpcInfo><vpcId>vpc-11111111</vpcId><ownerId>999988887777</ownerId><region>eu-west-1</region></accepterVpcInfo></item>
			</vpcPeeringConnectionSet>`
		}
		if data == "" {
			return nil, fmt.Errorf("unexpected AWS request action or page")
		}
		body := "<" + action + "Response>" + data + "</" + action + "Response>"
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}, nil
	})}
	inventory, err := discoverAWSCloudInventory(t.Context(), client, config, resolver)
	if err != nil || len(inventory.Resources) != 8 || len(inventory.Links) != 7 || requestCount != 8 {
		t.Fatalf("incomplete or foreign AWS inventory: %+v, requests=%d, %v", inventory, requestCount, err)
	}
	var viz Viz
	if err := ProjectCloudInventory(&viz, inventory); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, node := range viz.Nodes {
		ids[node.Label] = node.ID
		if node.Label == "pcx-22222222" && !node.Cloud.External {
			t.Fatal("foreign peer was treated as an inventoried endpoint")
		}
	}
	for _, edge := range viz.Edges {
		if edge.To == ids["pcx-22222222"] && edge.From != ids["vpc-22222222"] {
			t.Fatal("matching ID and CIDR joined the wrong peer account")
		}
	}
	if ids["vpc-33333333"] != "" || ids["vpc-11111111"] == ids["vpc-22222222"] {
		t.Fatal("owned or overlapping VPCs were merged by address")
	}

	ownerXML = "999988887777"
	requestCount = 0
	if _, err := discoverAWSCloudInventory(t.Context(), client, config, resolver); err == nil || requestCount != 1 {
		t.Fatal("wrong account could reach the regional inventory APIs", err)
	}
	ownerXML, failNAT = owner, true
	if partial, err := discoverAWSCloudInventory(t.Context(), client, config, resolver); err == nil || len(partial.Resources) != 0 {
		t.Fatal("a failed cloud page emitted a partial snapshot", err)
	}
	failNAT, missingNATSet = false, true
	if partial, err := discoverAWSCloudInventory(t.Context(), client, config, resolver); err == nil || len(partial.Resources) != 0 {
		t.Fatal("an omitted result set was mistaken for an empty cloud page", err)
	}
}
