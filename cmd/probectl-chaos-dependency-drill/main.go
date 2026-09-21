// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ctlplne/probectl/internal/chaos"
)

func main() {
	worker := flag.Bool("worker", false, "run the private pod-kill worker process")
	ackDelay := flag.Duration("worker-ack-delay", 150*time.Millisecond, "private worker ack delay")
	flag.Parse()

	if *worker {
		if err := chaos.RunDependencyDrillWorker(os.Stdin, os.Stdout, *ackDelay); err != nil {
			fmt.Fprintf(os.Stderr, "chaos dependency drill worker: %v\n", err)
			os.Exit(1)
		}
		return
	}

	_, err := chaos.RunDependencyDrill(context.Background(), os.Stdout, chaos.DependencyDrillOptions{
		WorkerCommand: []string{os.Args[0], "-worker", "-worker-ack-delay=150ms"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "chaos dependency drill: %v\n", err)
		os.Exit(1)
	}
}
