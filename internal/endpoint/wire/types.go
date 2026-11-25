// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package wire defines endpoint result types shared by the emitter and receiver.
package wire

const (
	TypeAttribution = "endpoint.attribution"
	TypeWiFi        = "endpoint.wifi"
	TypeGateway     = "endpoint.gateway"
	TypeLastMile    = "endpoint.lastmile"
	TypeSession     = "endpoint.session"
)

// IsResultType reports whether a type is one of the shipped DEM signals.
func IsResultType(resultType string) bool {
	switch resultType {
	case TypeAttribution, TypeWiFi, TypeGateway, TypeLastMile, TypeSession:
		return true
	default:
		return false
	}
}
