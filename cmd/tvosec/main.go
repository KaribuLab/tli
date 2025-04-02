package main

import (
	"fmt"
	"os"

	"github.com/KaribuLab/tvosec/internal"
	"github.com/gookit/slog"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use: "tvosec",
		Run: func(cmd *cobra.Command, args []string) {
			slog.Info("Hello, World!")
		},
	}
	// Add subcommands
	rootCmd.AddCommand(internal.NewScanCommand())
	rootCmd.AddCommand(internal.NewGitHookCommand())
	rootCmd.AddCommand(internal.NewSetupCommand())
	return rootCmd
}

func main() {
	rootCmd := NewRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
