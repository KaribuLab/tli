package internal

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Transcript struct {
	Terminal  interface{ CommitBlock(string) error }
	committed map[string]struct{}
}

func (t *Transcript) CommitOnce(key, text string) error {
	if _, ok := t.committed[key]; ok {
		return nil
	}
	if err := t.Terminal.CommitBlock(text); err != nil {
		return err
	}
	t.keepExisting(key)
	return nil
}
func (t *Transcript) keepExisting(key string) {
	if t.committed == nil {
		t.committed = make(map[string]struct{})
	}
	t.committed[key] = struct{}{}
}
func inlineLiteral(c TerminalOptions, s string) string { return uiText(s, c.ASCII) }
func inlineStyled(c TerminalOptions, s string, accent bool) string {
	s = SafeTerminalText(s)
	if c.Color && accent {
		return "\x1b[36m" + s + "\x1b[0m"
	}
	return s
}
func inlineRobot(c TerminalOptions, frame int) [4]string {
	if c.ASCII {
		return [4]string{" .----.", " |o  o|", " '----'", "  /  \\"}
	}
	return robotFrames[max(0, frame)%len(robotFrames)]
}
func inlineWelcomeLines(id RepositoryIdentity, identityErr error, c TerminalOptions, frame int) []string {
	robot := inlineRobot(c, frame)
	repo := SafeTerminalText(filepath.Base(id.Root))
	if id.Root == "" {
		repo = inlineLiteral(c, "Directorio actual")
	}
	branch := SafeTerminalText(id.Branch)
	if branch == "" {
		branch = inlineLiteral(c, "rama no disponible")
	}
	context := repo + inlineLiteral(c, " · ") + branch
	if identityErr != nil {
		context = inlineLiteral(c, "Abre TLI desde un repositorio válido")
	}
	labels := []string{"TITVO", inlineLiteral(c, "Una revisión antes de tu próximo paso."), context, inlineLiteral(c, "Conexión sin comprobar")}
	lines := make([]string, 4)
	for i := range lines {
		lines[i] = robot[i] + "  " + labels[i]
	}
	return lines
}
func RenderInlineWelcome(id RepositoryIdentity, e error, c TerminalOptions) string {
	return SafeTerminalText(strings.Join(inlineWelcomeLines(id, e, c, 0), "\n"))
}
func RenderInlineAction(m InlineModel, c TerminalOptions) string {
	label := map[ScanScope]string{ScopeStaged: "Cambios preparados", ScopeCommit: "Un commit", ScopeFull: "Repositorio completo"}[m.Options.Scope]
	if label == "" {
		label = "Revisión"
	}
	if m.PreviewOnly {
		label = "Preview · " + label
	}
	text := "> " + inlineLiteral(c, label)
	if m.Options.Scope == ScopeCommit {
		text += " " + SafeTerminalText(m.Options.Commit)
	}
	return SafeTerminalText(text)
}
func RenderInlinePreview(p ScanPlan, c TerminalOptions) string {
	lines := []string{inlineLiteral(c, fmt.Sprintf("%d incluidos · %d excluidos · %d bytes", len(p.Files), len(p.Excluded), p.TotalBytes))}
	for _, f := range p.Files[:min(5, len(p.Files))] {
		lines = append(lines, fmt.Sprintf("  %q (%d B)", f.Path, f.Size))
	}
	if len(p.Files) > 5 {
		lines = append(lines, inlineLiteral(c, fmt.Sprintf("  ... %d archivos más", len(p.Files)-5)))
	}
	for _, f := range p.Excluded[:min(3, len(p.Excluded))] {
		lines = append(lines, fmt.Sprintf("  - %q [%s]", f.Path, SafeTerminalText(f.Reason)))
	}
	if len(p.Excluded) > 3 {
		lines = append(lines, inlineLiteral(c, fmt.Sprintf("  ... %d exclusiones más", len(p.Excluded)-3)))
	}
	return SafeTerminalText(strings.Join(lines, "\n"))
}
func inlineCoverageLines(r StatusResult, c TerminalOptions) []string {
	label := "no registrada"
	if r.Result.Coverage != nil {
		label = "incompleta"
		if r.Result.Coverage.Complete {
			if len(r.Result.Coverage.Errors) > 0 || r.Result.Incomplete != nil {
				label = "incompleta (reportada completa)"
			} else {
				label = "completa"
			}
		}
	}
	lines := []string{inlineLiteral(c, "Cobertura: "+label)}
	if r.Result.Coverage != nil {
		for _, cause := range r.Result.Coverage.Errors {
			lines = append(lines, "  - "+SafeTerminalText(cause))
		}
	}
	if r.Result.Incomplete != nil {
		lines = append(lines, SafeTerminalText(r.Result.Incomplete.Message))
		for _, f := range r.Result.Incomplete.FilesNotFullyAnalyzed {
			lines = append(lines, inlineLiteral(c, "Sin completar: ")+SafeTerminalText(f))
		}
	}
	return lines
}
func RenderInlineOutcome(r StatusResult, e error, c TerminalOptions) string {
	var lines []string
	switch r.Result.Status {
	case "COMPLETED", "FAILED", "WARNING", "ERROR":
		lines = append(lines, inlineLiteral(c, "Estado reportado: ")+r.Result.Status, inlineLiteral(c, fmt.Sprintf("%d reportados · %d anotaciones recibidas", r.Result.NumberOfIssues, len(r.Result.Annotations))))
	default:
		lines = append(lines, inlineLiteral(c, "No se recibió resultado terminal."))
	}
	lines = append(lines, inlineCoverageLines(r, c)...)
	if len(r.Result.Annotations) == 0 && r.Result.NumberOfIssues > 0 {
		lines = append(lines, inlineLiteral(c, "Detalle: no se recibieron anotaciones; consulta el reporte."))
	}
	for _, a := range r.Result.Annotations[:min(5, len(r.Result.Annotations))] {
		lines = append(lines, fmt.Sprintf("  %s  %s (%q:%d)", SafeTerminalText(a.Severity), SafeTerminalText(a.Title), a.Path, a.Line))
	}
	if len(r.Result.Annotations) > 5 {
		lines = append(lines, inlineLiteral(c, "Ver detalle para consultar todos los hallazgos."))
	}
	if e != nil {
		lines = append(lines, inlineLiteral(c, "Aviso: ")+SafeTerminalText(e.Error()))
	}
	if r.ScanID != "" {
		lines = append(lines, "scan_id: "+SafeTerminalText(r.ScanID))
		if r.Result.Status == "" {
			lines = append(lines, inlineLiteral(c, "La tarea remota puede continuar; no se solicitó su cancelación."))
		}
	}
	if r.ReportUrl != "" {
		lines = append(lines, inlineLiteral(c, "Reporte: ")+SafeTerminalText(r.ReportUrl))
	}
	return SafeTerminalText(strings.Join(lines, "\n"))
}
