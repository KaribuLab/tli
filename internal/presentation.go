package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

func WriteResult(out io.Writer, r StatusResult, format string, hook bool) error {
	if format == "json" && !hook {
		return writeResultRaw(out, r, format, hook)
	}
	return writeHumanText(out, func(w io.Writer) error { return writeResultRaw(w, r, format, hook) })
}
func writeHumanText(out io.Writer, format func(io.Writer) error) error {
	var text strings.Builder
	if err := format(&text); err != nil {
		return err
	}
	_, err := io.WriteString(out, SafeTerminalText(text.String()))
	return err
}
func writeResultRaw(out io.Writer, r StatusResult, format string, hook bool) error {
	if hook {
		if r.ReportUrl != "" {
			_, e := fmt.Fprintln(out, r.ReportUrl)
			return e
		}
		return nil
	}
	if format == "json" {
		return json.NewEncoder(out).Encode(r)
	}
	if format != "markdown" {
		return fmt.Errorf("formato no válido")
	}
	if _, e := fmt.Fprintf(out, "# El escaneo finalizó con estado: %s\nReporte: %s\nNúmero de issues: %d\n", r.Result.Status, r.ReportUrl, r.Result.NumberOfIssues); e != nil {
		return e
	}
	if r.Result.Coverage != nil {
		if _, e := fmt.Fprintf(out, "Cobertura completa: %t\n", r.Result.Coverage.Complete); e != nil {
			return e
		}
	}
	if r.Result.Coverage != nil {
		for _, cause := range r.Result.Coverage.Errors {
			if _, e := fmt.Fprintf(out, "- %s\n", SafeTerminalText(cause)); e != nil {
				return e
			}
		}
	}
	if r.Result.Incomplete != nil {
		if _, e := fmt.Fprintf(out, "Análisis incompleto: %s\n", r.Result.Incomplete.Message); e != nil {
			return e
		}
	}
	for i, a := range r.Result.Annotations {
		if _, e := fmt.Fprintf(out, "\n## %d - %s\n%s\nSeveridad: %s\nRuta: %q · línea %d\n%s\nRecomendación: %s\n```\n%s\n```\n", i+1, a.Title, a.Description, a.Severity, a.Path, a.Line, a.Summary, a.Recommendation, a.Code); e != nil {
			return e
		}
	}
	return nil
}
func WritePlan(out io.Writer, p ScanPlan, format string) error {
	if format == "json" {
		return writePlanRaw(out, p, format)
	}
	return writeHumanText(out, func(w io.Writer) error { return writePlanRaw(w, p, format) })
}
func writePlanRaw(out io.Writer, p ScanPlan, format string) error {
	if format == "json" {
		return json.NewEncoder(out).Encode(p)
	}
	if format != "markdown" {
		return fmt.Errorf("formato no válido")
	}
	if _, e := fmt.Fprintf(out, "Repositorio: %s\nRama: %s · alcance: %s\nIncluidos: %d archivos · %d bytes\nExcluidos: %d\n", p.Repository.URL, p.Repository.Branch, p.Scope, len(p.Files), p.TotalBytes, len(p.Excluded)); e != nil {
		return e
	}
	for _, f := range p.Files {
		if _, e := fmt.Fprintf(out, "  + %q (%d bytes)\n", f.Path, f.Size); e != nil {
			return e
		}
	}
	for _, f := range p.Excluded {
		if _, e := fmt.Fprintf(out, "  - %q [%s]\n", f.Path, f.Reason); e != nil {
			return e
		}
	}
	return nil
}
