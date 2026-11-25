// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package branding

import "context"

// Lookup resolves presentation for an existing tenant authority. Callers
// already own the tenant and destination before looking up output branding.
type Lookup func(context.Context, string) Branding

type outputKey struct{}

func WithOutput(ctx context.Context, brand Branding) context.Context {
	return context.WithValue(ctx, outputKey{}, brand)
}

func Output(ctx context.Context) Branding {
	if brand, ok := ctx.Value(outputKey{}).(Branding); ok {
		return brand
	}
	return Default()
}

func (b Branding) DisplayName() string {
	if b.Customer != nil {
		return b.Customer.Name
	}
	return ProductName
}

func (b Branding) CustomerName() string {
	if b.Customer != nil {
		return b.Customer.Name
	}
	return ""
}

func (b Branding) AttributionLine() string {
	if b.Customer == nil {
		return ""
	}
	return Attribution + " (" + AttributionURL + ")"
}
