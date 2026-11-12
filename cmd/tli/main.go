package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/KaribuLab/tli/internal"
	"github.com/gookit/slog"
	"github.com/spf13/cobra"
)

var version = "dev"

func NewRootCommand() *cobra.Command {
	return rootWithTerminal(internal.TerminalOptions{})
}
func rootWithTerminal(terminal internal.TerminalOptions) *cobra.Command {
	slog.Configure(func(logger *slog.SugaredLogger) {})
	level := os.Getenv("TLI_LOG_LEVEL")
	if level == "" {
		level = "fatal"
	}
	slog.SetLevelByName(level)
	root := &cobra.Command{Use: "tli", Version: version, SilenceUsage: true, SilenceErrors: true}
	root.Args = cobra.NoArgs
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if !terminal.Interactive {
			return cmd.Help()
		}
		setup := func(ctx context.Context) error {
			c := internal.NewSetupCommand()
			c.SetIn(cmd.InOrStdin())
			c.SetOut(cmd.OutOrStdout())
			c.SetErr(cmd.ErrOrStderr())
			c.SetArgs(nil)
			return c.ExecuteContext(ctx)
		}
		menu := internal.Menu{In: cmd.InOrStdin(), Out: cmd.OutOrStdout(), Err: cmd.ErrOrStderr(), Terminal: terminal, Service: internal.ScanService{}, Setup: setup, Defaults: internal.ScanOptions{Path: ".", Remote: "origin", Scope: internal.ScopeFull, Limits: internal.DefaultLimits(), Timeout: time.Hour}}
		return menu.Run(cmd.Context())
	}
	root.SetVersionTemplate("tli {{.Version}}\n")
	root.AddCommand(internal.NewScanCommand(), internal.NewPreviewCommand(internal.ScanService{}), internal.NewGitHookCommand(), internal.NewSetupCommand())
	return root
}
func run(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	var inFile, outFile *os.File
	inFile, _ = in.(*os.File)
	outFile, _ = out.(*os.File)
	root := rootWithTerminal(internal.DetectTerminal(inFile, outFile, os.Getenv))
	root.SetIn(in)
	root.SetOut(out)
	root.SetErr(errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err != nil {
		fmt.Fprintln(errOut, err)
	}
	return internal.ExitCode(err)
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
