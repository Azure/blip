// Command kubectl-blip is a kubectl plugin to create and SSH into Blip
// sessions. See docs/kubectl-plugin.md.
package main

import (
	"os"

	"github.com/example/blip/internal/kubectlblip/cmd"
)

func main() { os.Exit(cmd.Main(os.Args[1:])) }
