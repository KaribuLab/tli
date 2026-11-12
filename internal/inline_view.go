package internal

import (
	"fmt"
	"strings"
	"unicode"
)

type InlineFrame struct {
	Lines                                          []string
	CursorVisible, ConsentVisible, WelcomeInActive bool
}

func inlineDimensions(m InlineModel) (int, int) {
	return min(max(0, m.Width-1), 255), min(max(0, m.Height-2), 98)
}
func inlineTail(s string, n int) string {
	r := []rune(SafeTerminalText(s))
	for CellWidth(string(r)) > n && len(r) > 0 {
		r = r[1:]
	}
	for len(r) > 0 && unicode.Is(unicode.Mn, r[0]) {
		r = r[1:]
	}
	return string(r)
}
func inlineDetailRows(m InlineModel, c TerminalOptions) []string {
	if m.Result == nil {
		return []string{inlineLiteral(c, "Resultado no disponible.")}
	}
	r := m.Result
	if m.Stage == "coverage" {
		lines := inlineCoverageLines(*r, c)
		if m.LastError != nil {
			lines = append(lines, inlineLiteral(c, "Aviso: ")+m.LastError.Error())
		}
		return lines
	}
	if len(r.Result.Annotations) == 0 {
		return []string{inlineLiteral(c, "No se recibió el detalle de los hallazgos.")}
	}
	a := r.Result.Annotations[max(0, min(m.Selection, len(r.Result.Annotations)-1))]
	severity := a.Severity
	if severity == "" {
		severity = inlineLiteral(c, "no registrada")
	}
	lines := []string{a.Title, inlineLiteral(c, "Severidad: ") + severity, fmt.Sprintf("%s:%d", strings.ReplaceAll(a.Path, "\n", "\\n"), a.Line), "", a.Description}
	if a.Summary != "" {
		lines = append(lines, "", a.Summary)
	}
	if a.Code != "" {
		lines = append(lines, "", inlineLiteral(c, "Código:"), a.Code)
	}
	if a.Recommendation != "" {
		lines = append(lines, "", inlineLiteral(c, "Recomendación:"), a.Recommendation)
	}
	return lines
}
func inlinePagerRows(m InlineModel, c TerminalOptions, width int) []string {
	var out []string
	for _, s := range inlineDetailRows(m, c) {
		out = append(out, WrapCells(s, width)...)
	}
	return out
}
func clampInline(m InlineModel) InlineModel {
	switch m.Stage {
	case "files":
		if m.Plan != nil {
			n := len(m.Plan.Files)
			if m.ListKind == "excluidos" {
				n = len(m.Plan.Excluded)
			}
			m.Selection = max(0, min(m.Selection, max(0, n-1)))
		}
	case "details", "coverage":
		if m.Result != nil && m.Stage == "details" {
			m.Selection = max(0, min(m.Selection, max(0, len(m.Result.Result.Annotations)-1)))
		}
		w, h := inlineDimensions(m)
		m.Offset = max(0, min(m.Offset, max(0, len(inlinePagerRows(m, TerminalOptions{}, w))-max(1, h-2))))
	}
	return m
}
func RenderInlineActive(model InlineModel, c TerminalOptions) InlineFrame {
	m := clampInline(model)
	width, limit := inlineDimensions(m)
	frame := InlineFrame{}
	if width < 1 || limit < 1 {
		return frame
	}
	add := func(s string) { frame.Lines = append(frame.Lines, ClipCells(s, width)) }
	literal := func(s string) string { return inlineLiteral(c, s) }
	if !m.GeometryReady || m.Width < 40 || m.Height < 10 {
		add(literal("Ajustando tamaño; envío desactivado."))
		if limit > 1 {
			add(literal("Ctrl+C interrumpir · Esc volver"))
		}
		return frame
	}
	switch m.Stage {
	case "actions", "scope", "result-actions":
		question := map[string]string{"actions": "¿Qué quieres revisar?", "scope": "¿Qué alcance quieres previsualizar?", "result-actions": "¿Qué quieres hacer ahora?"}[m.Stage]
		choices := inlineChoices(m)
		if m.Stage == "actions" && !m.WelcomeCommitted {
			welcome := inlineWelcomeLines(m.Identity, m.IdentityError, c, 0)
			if len(welcome)+max(1, len(choices))+4 <= limit {
				pose := 0
				if c.Animate && m.MotionTick%8 == 7 {
					pose = 2
				}
				for _, s := range inlineWelcomeLines(m.Identity, m.IdentityError, c, pose) {
					add(s)
				}
				add("")
				frame.WelcomeInActive = true
			}
		}
		add(literal(question))
		if m.LastError != nil && m.Stage == "actions" && len(frame.Lines)+4 < limit {
			add(literal("Aviso: ") + m.LastError.Error())
		}
		rows := max(1, limit-len(frame.Lines)-2)
		selection := max(0, min(m.Selection, max(0, len(choices)-1)))
		start := max(0, min(selection-rows+1, max(0, len(choices)-rows)))
		if len(choices) == 0 {
			add(literal("Sin coincidencias. No se ejecutará ninguna acción."))
		} else {
			for i := start; i < min(len(choices), start+rows); i++ {
				prefix := "  "
				if i == selection {
					prefix = "> "
				}
				line := prefix + literal(choices[i].Label)
				if choices[i].Hint != "" {
					line += "  " + literal(choices[i].Hint)
				}
				add(line)
			}
		}
		add(literal("↑↓ elegir · Enter continuar · Esc volver/salir"))
		add("> " + inlineTail(m.Query, max(0, width-2)))
		frame.CursorVisible = true
	case "commit":
		add(literal("Referencia del commit (HEAD por defecto)"))
		add(literal("Enter: previsualizar · Esc: volver"))
		add("> " + inlineTail(m.DraftCommit, max(0, width-2)))
		frame.CursorVisible = true
	case "loading":
		add(literal("Preparando preview local..."))
		add(literal("No se está enviando código."))
		add(literal("Ctrl+C interrumpir · Esc volver"))
	case "confirm":
		if m.Plan == nil {
			add(literal("No hay preview disponible."))
			break
		}
		lines := []string{literal(fmt.Sprintf("%s · %d archivos · %d bytes", scopeLabel(m.Options.Scope), len(m.Plan.Files), m.Plan.TotalBytes))}
		lines = append(lines, WrapCells(literal("El código seleccionado se subirá a Titvo."), width)...)
		lines = append(lines, literal("¿Iniciar este análisis?"))
		choices := InlineActions(m)
		hasBack, hasSend := false, false
		for i, a := range choices {
			prefix := "  "
			if i == m.Selection {
				prefix = "> "
			}
			lines = append(lines, prefix+literal(a.Label))
			if a.ID == "back" {
				hasBack = true
			}
			if a.ID == "send" {
				hasSend = true
			}
		}
		lines = append(lines, literal("↑↓ elegir · Enter confirmar · Esc volver"))
		frame.ConsentVisible = hasBack && hasSend && len(lines) <= limit
		for _, line := range lines {
			add(line)
		}
	case "files":
		n := 0
		if m.Plan != nil {
			n = len(m.Plan.Files)
			if m.ListKind == "excluidos" {
				n = len(m.Plan.Excluded)
			}
		}
		add(literal(fmt.Sprintf("Archivos %s (%d)", m.ListKind, n)))
		rows := max(1, limit-2)
		start := max(0, min(m.Selection-rows+1, max(0, n-rows)))
		if n == 0 {
			add(literal("No hay archivos en esta lista."))
		} else {
			for i := start; i < min(n, start+rows); i++ {
				prefix := "  "
				if i == m.Selection {
					prefix = "> "
				}
				if m.ListKind == "excluidos" {
					f := m.Plan.Excluded[i]
					add(fmt.Sprintf("%s%q [%s]", prefix, f.Path, f.Reason))
				} else {
					f := m.Plan.Files[i]
					add(fmt.Sprintf("%s%q (%d B)", prefix, f.Path, f.Size))
				}
			}
		}
		add(literal("↑↓ archivo · Tab incluidos/excluidos · Esc volver"))
	case "details", "coverage":
		title := literal("Cobertura")
		if m.Stage == "details" && m.Result != nil {
			title = literal(fmt.Sprintf("Hallazgo %d de %d", min(m.Selection+1, len(m.Result.Result.Annotations)), len(m.Result.Result.Annotations)))
		}
		add(title)
		lines := inlinePagerRows(m, c, width)
		rows := max(1, limit-2)
		offset := max(0, min(m.Offset, max(0, len(lines)-rows)))
		for _, s := range lines[offset:min(len(lines), offset+rows)] {
			add(s)
		}
		add(literal(fmt.Sprintf("%d/%d · PgUp/PgDn detalle · ↑↓ hallazgo · Esc", min(offset+rows, len(lines)), len(lines))))
	case "running":
		phase := map[string]string{"preparing": "Preparando snapshot", "uploading": "Subiendo código", "analyzing": "Esperando resultado del análisis", "completed": "Análisis terminado"}[m.Progress.Phase]
		if phase == "" {
			phase = "Esperando estado"
		}
		marker := ">"
		if c.Animate {
			frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"}
			marker = frames[m.MotionTick%uint64(len(frames))]
			if c.ASCII {
				marker = []string{"|", "/", "-", "\\"}[m.MotionTick%4]
			}
		}
		add(marker + " " + literal(phase))
		info := []string{literal(fmt.Sprintf("%d archivos · %d bytes", m.Progress.Files, m.Progress.Bytes)), literal(fmt.Sprintf("Tiempo: %s", m.Progress.Elapsed.Round(1e9)))}
		if m.Progress.ScanID != "" {
			info = append(info, "scan_id: "+m.Progress.ScanID)
		} else {
			info = append(info, literal("ID de escaneo pendiente"))
		}
		if limit >= 9 {
			pose := 0
			if c.Animate {
				pose = int(m.MotionTick % 4)
			}
			robot := inlineRobot(c, pose)
			for i := range robot {
				text := robot[i]
				if i < len(info) {
					text += "  " + info[i]
				}
				add(text)
			}
		} else {
			for _, s := range info {
				add(s)
			}
		}
		add(literal("Ctrl+C detiene espera · Esc cancelar y volver"))
		add(literal("La tarea remota puede continuar."))
	}
	if len(frame.Lines) > limit {
		frame.Lines = frame.Lines[:limit]
		frame.ConsentVisible = false
	}
	if c.Color {
		for i, line := range frame.Lines {
			if strings.HasPrefix(line, "> ") || strings.Contains(line, "TITVO") {
				frame.Lines[i] = inlineStyled(c, line, true)
			}
		}
	}
	return frame
}
func InlineConsentVisible(m InlineModel) bool {
	if m.Stage != "confirm" || m.Plan == nil || m.PreviewOnly || !m.GeometryReady {
		return false
	}
	return RenderInlineActive(m, TerminalOptions{Interactive: true}).ConsentVisible
}
