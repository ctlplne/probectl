// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ctlplne/probectl/internal/i18n"
)

const helpGroupNameWidth = 24

func renderUsage(locale string) string {
	return i18n.T(locale, "cli.usage", map[string]string{
		"surface_commands": renderSurfaceCommandInventory(locale),
	})
}

func renderSurfaceCommandInventory(locale string) string {
	names := make([]string, 0, len(surfaceCommands))
	for name := range surfaceCommands {
		names = append(names, name)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, name := range names {
		spec := surfaceCommands[name]
		fmt.Fprintf(&b, "  %-*s %s\n", helpGroupNameWidth, spec.Name, localizedSurfaceSummary(locale, spec))
	}
	return b.String()
}

func localizedSurfaceSummary(locale string, spec surfaceCommand) string {
	key := "cli.surface." + spec.Name
	summary := i18n.T(locale, key, nil)
	if summary == key {
		return spec.Summary
	}
	return summary
}
