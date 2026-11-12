// Command slotdev runs the slot supervisor like `blipd slot`, for tests.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/blip/internal/slot"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	err := slot.Main(ctx, os.Args[1:])
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "slotdev:", err)
	var ee *slot.ExitError
	if errors.As(err, &ee) {
		os.Exit(ee.ExitCode())
	}
	os.Exit(1)
}
