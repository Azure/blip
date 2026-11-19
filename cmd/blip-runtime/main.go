// Command blip-runtime runs one blip VM inside a VM pod.
//
//	blip-runtime            supervise Cloud Hypervisor (see the README)
//	blip-runtime api-proxy  serve the VM-only HTTP proxy for the API and endpoints
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Azure/blip/internal/apiproxy"
	"github.com/Azure/blip/internal/runtime"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("blip-runtime: ")
	if len(os.Args) == 2 && os.Args[1] == "api-proxy" {
		cfg, err := apiproxy.ConfigFromEnv()
		if err != nil {
			log.Fatal(err)
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
		defer cancel()
		if err := apiproxy.Run(ctx, cfg); err != nil {
			log.Fatal(err)
		}
		return
	}
	o := runtime.OptionsFromEnv()
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: blip-runtime [api-proxy]")
		os.Exit(2)
	}
	if err := runtime.Run(o); err != nil {
		log.Fatal(err)
	}
}
