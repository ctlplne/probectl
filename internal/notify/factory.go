// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package notify

import "strings"

// providerCaps is the supported provider set and what each does.
var providerCaps = map[string]Capability{
	"pagerduty":  CapabilityPager,
	"opsgenie":   CapabilityPager,
	"slack":      CapabilityChat,
	"teams":      CapabilityChat,
	"servicenow": CapabilityTicket,
	"jira":       CapabilityTicket,
}

// knownProvider reports whether name is a supported connector provider.
func knownProvider(name string) bool {
	_, ok := providerCaps[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// NewConnector builds a connector for a provider over endpoint + secret. A nil
// client uses the hardened default. ok is false for an unknown provider.
func NewConnector(provider, endpoint, secret string, client Doer) (Connector, bool) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "pagerduty":
		return newPagerDuty(endpoint, secret, client), true
	case "opsgenie":
		return newOpsgenie(endpoint, secret, client), true
	case "slack":
		return newChat("slack", endpoint, client), true
	case "teams":
		return newChat("teams", endpoint, client), true
	case "servicenow":
		return newServiceNow(endpoint, secret, client), true
	case "jira":
		return newJira(endpoint, secret, client), true
	default:
		return nil, false
	}
}
