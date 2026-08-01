// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ctlplne/probectl/pkg/sdk"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	client := sdk.NewClient(
		envOr("PROBECTL_API_URL", "https://probectl.example"),
		sdk.WithToken(os.Getenv("PROBECTL_API_TOKEN")),
		sdk.WithTenant(os.Getenv("PROBECTL_TENANT")),
	)
	tests, err := client.ListTests(ctx, sdk.ListTestsRequest{Limit: sdk.Int(50)})
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "list tests: %v\n", err)
		os.Exit(1)
	}
	for _, test := range tests.Items {
		fmt.Printf("%s\t%s\t%s\n", test.Id, test.Name, test.Type)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
