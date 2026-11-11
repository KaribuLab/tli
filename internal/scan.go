package internal

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewScanCommand() *cobra.Command { return newScanCommand(ScanService{}) }
func newScanCommand(service ScanService) *cobra.Command {
	cmd := &cobra.Command{Use: "scan", SilenceUsage: true, SilenceErrors: true}
	addScanFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return runScanWithService(cmd, args, service) }
	return cmd
}
func RunScanCommand(cmd *cobra.Command, args []string) error {
	return runScanWithService(cmd, args, ScanService{})
}
func scanOptions(cmd *cobra.Command) (ScanOptions, error) {
	if (cmd.Flags().Changed("full") && (cmd.Flags().Changed("commit") || cmd.Flags().Changed("staged"))) || (cmd.Flags().Changed("commit") && cmd.Flags().Changed("staged")) {
		return ScanOptions{}, fmt.Errorf("selecciona un solo alcance")
	}
	o := ScanOptions{Scope: ScopeFull, Limits: DefaultLimits()}
	o.Path, _ = cmd.Flags().GetString("path")
	o.Remote, _ = cmd.Flags().GetString("remote")
	o.Commit, _ = cmd.Flags().GetString("commit")
	staged, _ := cmd.Flags().GetBool("staged")
	full, _ := cmd.Flags().GetBool("full")
	if staged {
		o.Scope = ScopeStaged
	} else if o.Commit != "" {
		o.Scope = ScopeCommit
	} else if !full {
		return o, fmt.Errorf("selecciona un alcance")
	}
	o.Limits.MaxFileBytes, _ = cmd.Flags().GetInt64("max-file-bytes")
	o.Limits.MaxTotalBytes, _ = cmd.Flags().GetInt64("max-total-bytes")
	o.Limits.MaxFiles, _ = cmd.Flags().GetInt("max-files")
	o.Timeout, _ = cmd.Flags().GetDuration("timeout")
	if o.Timeout <= 0 {
		return o, fmt.Errorf("timeout debe ser positivo")
	}
	return o, ValidateLimits(o.Limits)
}
func runScanWithService(cmd *cobra.Command, args []string, s ScanService) error {
	if len(args) > 0 {
		return fmt.Errorf("scan no acepta argumentos posicionales")
	}
	o, e := scanOptions(cmd)
	if e != nil {
		return e
	}
	format, _ := cmd.Flags().GetString("output")
	if format != "json" && format != "markdown" {
		return fmt.Errorf("formato no válido")
	}
	hook, _ := cmd.Flags().GetBool("githook")
	result, e := s.Scan(cmd.Context(), o, "", nil)
	if result.ScanID != "" {
		if err := WriteResult(cmd.OutOrStdout(), result, format, hook); err != nil {
			return err
		}
	}
	return e
}
