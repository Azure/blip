package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	})))

	rootCmd := newRootCmd()
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "kubectl-blip",
		Short:         "kubectl plugin for Blip VM pool management",
		Long:          "Generates VirtualMachinePool manifests for the Blip VM pool.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(newGeneratePoolCmd())
	return cmd
}
