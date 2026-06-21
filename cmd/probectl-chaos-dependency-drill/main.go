// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/chaos"
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
