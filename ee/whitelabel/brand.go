// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// Package whitelabel stores customer presentation owned by the provider.
package whitelabel

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image/png"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/branding"
)

const maxLogoBytes = 32 << 10

var (
	dnsLabel          = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	ipv4LikeLastLabel = regexp.MustCompile(`^([0-9]+|0x[0-9a-f]*)$`)
)

// Brand is the complete provider-editable document. Attribution lives in the
// renderer and has no corresponding field in the document.
type Brand struct {
	Name        string            `json:"name"`
	LogoDataURI string            `json:"logo_data_uri,omitempty"`
	Colors      map[string]string `json:"colors,omitempty"`
	Domain      string            `json:"domain,omitempty"`
}

func Normalize(input Brand, deployment map[string]string) (Brand, error) {
	input.Name = strings.TrimSpace(input.Name)
	if len(input.Name) > 120 || !utf8.ValidString(input.Name) ||
		strings.IndexFunc(input.Name, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return Brand{}, errors.New("brand name must be at most 120 bytes of display text")
	}
	if input.Domain != "" {
		input.Domain = domainName(input.Domain)
		if input.Domain == "" {
			return Brand{}, errors.New("brand domain must be a DNS hostname")
		}
	}
	if input.LogoDataURI != "" && !validLogo(input.LogoDataURI) {
		return Brand{}, errors.New("brand logo must be an inline PNG of at most 32 KiB and 512 by 512 pixels")
	}
	if err := branding.ValidateColorOverrides(input.Colors, deployment); err != nil {
		return Brand{}, err
	}
	return input, nil
}

// Presentation projects safe customer fields alongside the fixed product
// identity. A color-only or domain-only brand still carries attribution.
func (b Brand) Presentation(deployment map[string]string, onDomain bool) branding.Branding {
	if b.Name == "" && b.LogoDataURI == "" && len(b.Colors) == 0 && b.Domain == "" {
		return branding.Deployment(deployment)
	}
	out := branding.Deployment(deployment)
	if branding.ValidateColorOverrides(b.Colors, deployment) == nil && len(b.Colors) > 0 {
		if out.TokenOverrides == nil {
			out.TokenOverrides = map[string]string{}
		}
		for name, value := range b.Colors {
			out.TokenOverrides[name] = value
		}
	}
	name := b.Name
	if name == "" {
		name = branding.ProductName
	}
	out.Customer = &branding.CustomerIdentity{Name: name, LogoDataURI: b.LogoDataURI}
	out.CustomerDomain = onDomain
	return out
}

func validLogo(uri string) bool {
	body, hasPrefix := strings.CutPrefix(uri, "data:image/png;base64,")
	if !hasPrefix || len(body) > base64.StdEncoding.EncodedLen(maxLogoBytes) {
		return false
	}
	data, err := base64.StdEncoding.Strict().DecodeString(body)
	if err != nil || len(data) > maxLogoBytes || base64.StdEncoding.EncodeToString(data) != body {
		return false
	}
	size, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil || size.Width < 1 || size.Height < 1 || size.Width > 512 || size.Height > 512 {
		return false
	}
	_, err = png.Decode(bytes.NewReader(data))
	return err == nil
}

func domainName(raw string) string {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(name) > 253 {
		return ""
	}
	labels := strings.Split(name, ".")
	// Browser HTTPS redirects interpret decimal and hexadecimal final labels
	// as IPv4 syntax, including forms Go's net.ParseIP would reject.
	if len(labels) < 2 || ipv4LikeLastLabel.MatchString(labels[len(labels)-1]) {
		return ""
	}
	for _, label := range labels {
		if !dnsLabel.MatchString(label) {
			return ""
		}
	}
	return name
}

func requestDomain(host string) string {
	if name, port, err := net.SplitHostPort(host); err == nil {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return ""
		}
		host = name
	}
	return domainName(host)
}
