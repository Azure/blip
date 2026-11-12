// Command blipd is the Blip controller, node daemon and slot supervisor.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/blip/internal/controller"
	"github.com/example/blip/internal/node"
	"github.com/example/blip/internal/slot"
)

const usage = "usage: blipd controller|node|slot [probe] [flags]"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	var run func(context.Context, []string) error
	switch os.Args[1] {
	case "controller":
		run = controller.Main
	case "node":
		run = node.Main
	case "slot":
		run = slot.Main // handles "slot probe" itself
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err := run(ctx, os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "blipd:", err)
		var ee *slot.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		os.Exit(1)
	}
}
