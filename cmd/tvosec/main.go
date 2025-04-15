package main

import (
	"fmt"
	"os"

	"github.com/KaribuLab/tvosec/internal"
	"github.com/gookit/slog"
	"github.com/spf13/cobra"
)

func NewRootCommand() *cobra.Command {
	slog.Configure(func(logger *slog.SugaredLogger) {})
	logLevel, ok := os.LookupEnv("TLI_LOG_LEVEL")
	if ok {
		slog.SetLevelByName(logLevel)
	} else {
		slog.SetLevelByName("info")
	}
	rootCmd := &cobra.Command{
		Use: "tli",
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
