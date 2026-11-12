// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package bgp_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

// Real HTTPS pages use the current tenant session and the actual source-joined
// hand fixture. Accessibility is required on each final populated result in
// both shipped themes; no mocked response or missing report can qualify it.
func renderPeeringRouterEstimates(t *testing.T, st *shipped.Stack, registrations []edgeFlowRegistration, ids []map[uint32]string, links []roleRouterLink, input flow.PeeringEstimateInput) {
	t.Helper()
	const panel = "[data-peering-estimate]"
	const result = "[aria-label='Peering estimate result']"
	for lane, reg := range registrations {
		for _, theme := range []string{"light", "dark"} {
			t.Run("peering-ui/"+strconv.Itoa(lane)+"/"+theme, func(t *testing.T) {
				rate, foreignRate := "101.000 Gbps", "303.000 Gbps"
				if lane == 1 {
					rate, foreignRate = foreignRate, rate
				}
				positive := []string{"Complete observed input classification.", rate, "20 / 20", ids[lane][links[0].index], ids[lane][links[2].index], "Exact combined rate:", "Per-interface percentiles must not be added."}
				steps := []testsupport.RenderStep{
					{Click: "Configure a hypothetical peering", Summary: true, Within: panel},
					{Select: panel + " select >> nth=0", Value: reg.contextID},
					{Select: panel + " select >> nth=1", Value: ids[lane][links[1].index]},
					{Fill: panel + " input >> nth=0", Value: strconv.Itoa(originA)},
					{Fill: panel + " input >> nth=1", Value: input.IXID},
					{Fill: panel + " input >> nth=2", Value: input.LANID},
					{Fill: panel + " input >> nth=3", Value: input.From.Format(time.RFC3339Nano)},
					{Fill: panel + " input >> nth=4", Value: input.To.Format(time.RFC3339Nano)},
					{Fill: panel + " input >> nth=5", Value: strconv.Itoa(input.BucketSeconds)},
					{Select: panel + " select >> nth=3", Value: input.DataSeries},
				}
				for _, direction := range []string{"inbound", "outbound"} {
					steps = append(steps,
						testsupport.RenderStep{Select: panel + " select >> nth=2", Value: direction},
						testsupport.RenderStep{Click: "Estimate observed peering traffic", Within: panel, Expect: positive, Absent: []string{foreignRate, registrations[1-lane].deviceID}, ExpectWithin: result},
					)
				}
				steps = append(steps,
					testsupport.RenderStep{Fill: panel + " input >> nth=3", Value: input.From.Add(-5 * time.Minute).Format(time.RFC3339Nano)},
					testsupport.RenderStep{Click: "Estimate observed peering traffic", Within: panel, Expect: []string{"Missing observed intervals: no p95 is available.", "20 / 21", "Unavailable"}, Absent: []string{rate, foreignRate}, ExpectWithin: result},
					testsupport.RenderStep{Fill: panel + " input >> nth=3", Value: input.From.Format(time.RFC3339Nano)},
					testsupport.RenderStep{Click: "Estimate observed peering traffic", Within: panel, Expect: positive, Absent: []string{foreignRate}, ExpectWithin: result},
					testsupport.RenderStep{Click: "Complete target evidence references", Summary: true, Within: result, Expect: []string{"All prefix sources (2)", "All membership sources (1)"}, ExpectWithin: result},
				)
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL: st.BaseURL + "/ui/explore?native_flow=1", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: reg.cookie}},
					TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, Theme: theme, Accessibility: true, TimeoutMs: 90000,
					Expect: []string{"Flow explorer", "Peering estimate · preview"}, Absent: []string{registrations[1-lane].deviceID}, Steps: steps,
					Controls: []testsupport.RenderControl{{Role: "textbox", Name: "All prefix sources (2)"}, {Role: "textbox", Name: "All membership sources (1)"}},
				})
			})
		}
	}
}
