// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Command kubectl-blip is the Blip kubectl plugin, run as `kubectl blip`.
package main

import (
	"context"
	"flag"
	"io"
	"os"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"

	"github.com/Azure/blip/internal/cli"
)

func main() {
	// client-go logs connection teardown noise (closed connections) that is
	// expected when a stream ends. Errors that matter are returned to the CLI
	// and printed there.
	fs := flag.NewFlagSet("klog", flag.ContinueOnError)
	klog.InitFlags(fs)
	_ = fs.Set("logtostderr", "false")
	_ = fs.Set("alsologtostderr", "false")
	_ = fs.Set("stderrthreshold", "FATAL")
	klog.SetOutput(io.Discard)
	utilruntime.ErrorHandlers = nil
	os.Exit(cli.Main(context.Background(), cli.DefaultEnv(), os.Args[1:]))
}
