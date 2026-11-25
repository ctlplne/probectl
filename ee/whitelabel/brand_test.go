// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package whitelabel

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"testing"

	"github.com/ctlplne/probectl/internal/branding"
)

func customerBrandFixtureLogo(t *testing.T, width int) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, image.NewRGBA(image.Rect(0, 0, width, 4))); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buffer.Bytes())
}

func TestCustomerBrandValidatesThePresentationAndReservesAttribution(t *testing.T) {
	logo := customerBrandFixtureLogo(t, 4)
	input := Brand{Name: " Northstar ", Domain: " Portal.Customers.Example. ",
		LogoDataURI: logo, Colors: map[string]string{"--primary": "28 85% 30%", "--primary-foreground": "0 0% 100%"}}
	normalized, err := Normalize(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := normalized.Presentation(nil, true)
	if normalized.Domain != "portal.customers.example" || got.ProductName != "probectl" ||
		got.Customer == nil || got.Customer.Name != "Northstar" || got.Customer.LogoDataURI != logo ||
		!got.CustomerDomain || got.TokenOverrides["--primary"] != input.Colors["--primary"] ||
		got.AttributionLine() != branding.Attribution+" ("+branding.AttributionURL+")" {
		t.Fatal("the customer fields or fixed probectl attribution were lost")
	}
	for _, bad := range []Brand{
		{Name: "Northstar\u202e"},
		{Domain: "https://northstar.example"},
		{Domain: "127.0.0.1"},
		{Domain: "192.0.513"},
		{Domain: "192.0X201."},
		{Domain: "192.0x"},
		{Domain: "customer.123"},
		{LogoDataURI: "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte("<svg/>"))},
		{Colors: map[string]string{"--powered-by-opacity": "0 0% 0%"}},
		{Colors: map[string]string{"--primary": "0 0% 99%", "--primary-foreground": "0 0% 100%"}},
	} {
		if _, err := Normalize(bad, nil); err == nil {
			t.Fatalf("accepted disallowed brand field %#v", bad)
		}
	}
	numbered, err := Normalize(Brand{Domain: "123.customers.example"}, nil)
	if err != nil || numbered.Domain != "123.customers.example" {
		t.Fatalf("a DNS name with a numeric subdomain was rejected: %+v, %v", numbered, err)
	}
	domainOnly := (Brand{Domain: "portal.customers.example"}).Presentation(nil, true)
	if domainOnly.Customer == nil || domainOnly.AttributionLine() == "" {
		t.Fatal("a domain-only customer avoids attribution")
	}
}
