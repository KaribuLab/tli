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
		Use: "tli",
	}
	// Add subcommands
	rootCmd.AddCommand(internal.NewScanCommand())
	rootCmd.AddCommand(internal.NewGitHookCommand())
	rootCmd.AddCommand(internal.NewSetupCommand())
	return rootCmd
}

func main() {
	// Configurar el nivel de log por defecto a Info
	slog.Configure(func(logger *slog.SugaredLogger) {
		fmt.Println("Configurando nivel de log a INFO")
	})
	slog.SetLogLevel(slog.InfoLevel)

	rootCmd := NewRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
