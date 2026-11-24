// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Command blip-runtime runs one blip VM inside a VM pod.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Azure/blip/internal/runtime"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("blip-runtime: ")
	if len(os.Args) > 1 && os.Args[1] == "proxy-init" {
		if err := proxyInit(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: blip-runtime [proxy-init --dir DIR --credentials NAMES]")
		os.Exit(2)
	}
	if err := runtime.Run(runtime.OptionsFromEnv()); err != nil {
		log.Fatal(err)
	}
}
