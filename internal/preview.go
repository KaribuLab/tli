package internal

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func addScanFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("path", "p", ".", "Path to scan")
	cmd.Flags().StringP("output", "o", "markdown", "Output: markdown or json")
	cmd.Flags().StringP("remote", "r", "origin", "Local remote metadata (no network)")
	cmd.Flags().StringP("commit", "c", "", "Commit hash to scan")
	cmd.Flags().BoolP("staged", "s", false, "Staged files only")
	cmd.Flags().BoolP("githook", "g", false, "Githook URL-only output")
	cmd.Flags().BoolP("full", "f", true, "Full tracked working tree")
	limits := DefaultLimits()
	cmd.Flags().Int64("max-file-bytes", limits.MaxFileBytes, "Maximum bytes per file")
	cmd.Flags().Int64("max-total-bytes", limits.MaxTotalBytes, "Maximum total included bytes")
	cmd.Flags().Int("max-files", limits.MaxFiles, "Maximum included files")
	cmd.Flags().Duration("timeout", time.Hour, "Scan deadline")
}
func NewPreviewCommand(service ScanService) *cobra.Command {
	cmd := &cobra.Command{Use: "preview", SilenceUsage: true, SilenceErrors: true}
	addScanFlags(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("preview no acepta argumentos posicionales")
		}
		format, _ := cmd.Flags().GetString("output")
		hook, _ := cmd.Flags().GetBool("githook")
		if hook {
			return fmt.Errorf("preview no admite --githook")
		}
		if format != "json" && format != "markdown" {
			return fmt.Errorf("formato no válido")
		}
		o, e := scanOptions(cmd)
		if e != nil {
			return e
		}
		p, e := service.Preview(cmd.Context(), o)
		if e != nil {
			return e
		}
		return WritePlan(cmd.OutOrStdout(), p, format)
	}
	return cmd
}
