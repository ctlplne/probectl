// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/imfeelingtheagi/probectl/pkg/sdk"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := sdk.NewClient(
		envOr("PROBECTL_API_URL", "https://probectl.example"),
		sdk.WithToken(os.Getenv("PROBECTL_API_TOKEN")),
		sdk.WithTenant(os.Getenv("PROBECTL_TENANT")),
	)
	tests, err := client.ListTests(ctx, sdk.ListTestsRequest{Limit: sdk.Int(50)})
	if err != nil {
		log.Fatal(err)
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
