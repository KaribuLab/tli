package main

import (
	"fmt"
	"os"

	"github.com/KaribuLab/tli/internal"
	"github.com/gookit/slog"
	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func NewRootCommand() *cobra.Command {
	slog.Configure(func(logger *slog.SugaredLogger) {})
	logLevel, ok := os.LookupEnv("TLI_LOG_LEVEL")
	if ok {
		slog.SetLevelByName(logLevel)
	} else {
		slog.SetLevelByName("fatal")
	}
	rootCmd := &cobra.Command{
		Use:     "tli",
		Version: version,
	}
	rootCmd.SetVersionTemplate("tli {{.Version}}\n")
	// Add subcommands
	rootCmd.AddCommand(internal.NewScanCommand())
	rootCmd.AddCommand(internal.NewGitHookCommand())
	rootCmd.AddCommand(internal.NewSetupCommand())
	return rootCmd
}

func main() {
	rootCmd := NewRootCommand()
	// Configurar Cobra para no imprimir errores automáticamente
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	if err := rootCmd.Execute(); err != nil {
		// Escribir errores a stderr en lugar de stdout
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
