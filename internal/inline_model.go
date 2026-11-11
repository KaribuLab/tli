package internal

import (
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

type InlineModel struct {
	Options                                                                        ScanOptions
	Identity                                                                       RepositoryIdentity
	IdentityError                                                                  error
	Stage, Query, DraftCommit, ListKind                                            string
	Selection, Offset, Width, Height                                               int
	Revision, MotionTick                                                           uint64
	Busy, PreviewOnly, ExitRequested, Interrupted, GeometryReady, WelcomeCommitted bool
	Plan                                                                           *ScanPlan
	Result                                                                         *StatusResult
	Progress                                                                       ProgressEvent
	LastError                                                                      error
}
type InlineAction struct{ ID, Label, Hint string }
type InlineEvent struct {
	Kind, Key     string
	Width, Height int
	Revision      uint64
	Plan          *ScanPlan
	Result        *StatusResult
	Progress      ProgressEvent
	Elapsed       time.Duration
	Err           error
}
type InlineEffect struct {
	Kind        string
	Options     ScanOptions
	Fingerprint string
	Revision    uint64
}

func NewInlineModel(o ScanOptions, id RepositoryIdentity, identityErr error, w, h int) InlineModel {
	return InlineModel{Options: o, Identity: id, IdentityError: identityErr, Stage: "actions", DraftCommit: "HEAD", ListKind: "incluidos", Width: w, Height: h}
}
func InlineActions(m InlineModel) []InlineAction {
	scopes := []InlineAction{{"staged", "Cambios preparados", "contenido exacto de staged"}, {"commit", "Un commit", "elige una referencia"}, {"full", "Repositorio completo", "working tree versionado"}}
	switch m.Stage {
	case "actions":
		return append(scopes, InlineAction{"preview", "Solo previsualizar", "sin enviar código"}, InlineAction{"setup", "Configurar conexión", ""}, InlineAction{"quit", "Salir", ""})
	case "scope":
		return scopes
	case "confirm":
		actions := []InlineAction{{"back", "Volver", "opción predeterminada"}}
		if m.Plan != nil && len(m.Plan.Files) > 0 && !m.PreviewOnly {
			actions = append(actions, InlineAction{"send", "Enviar a Titvo e iniciar", ""})
		}
		return append(actions, InlineAction{"files", "Revisar lista completa", ""})
	case "result-actions":
		var actions []InlineAction
		if m.Result != nil && len(m.Result.Result.Annotations) > 0 {
			actions = append(actions, InlineAction{"details", "Ver detalle de los hallazgos", ""})
		}
		return append(actions, InlineAction{"coverage", "Revisar cobertura", ""}, InlineAction{"new", "Otra revisión", ""}, InlineAction{"quit", "Salir", ""})
	}
	return nil
}
func searchFold(s string) string {
	var out strings.Builder
	for _, r := range norm.NFD.String(strings.ToLower(s)) {
		if !unicode.Is(unicode.Mn, r) {
			out.WriteRune(r)
		}
	}
	return out.String()
}
func FilterInlineActions(actions []InlineAction, query string) []InlineAction {
	query = searchFold(strings.TrimSpace(query))
	var out []InlineAction
	for _, a := range actions {
		if strings.Contains(searchFold(a.Label+" "+a.Hint), query) {
			out = append(out, a)
		}
	}
	return out
}
func inlineSearchStage(m InlineModel) bool {
	return m.Stage == "actions" || m.Stage == "scope" || m.Stage == "result-actions"
}
func inlineChoices(m InlineModel) []InlineAction {
	actions := InlineActions(m)
	if inlineSearchStage(m) {
		return FilterInlineActions(actions, m.Query)
	}
	return actions
}
func inlineEffect(m InlineModel, kind string) InlineEffect {
	e := InlineEffect{Kind: kind, Options: m.Options, Revision: m.Revision}
	if m.Plan != nil {
		e.Fingerprint = m.Plan.Fingerprint
	}
	return e
}
func inlineHome(m InlineModel) InlineModel {
	m.Stage = "actions"
	m.Query = ""
	m.Selection = 0
	m.Offset = 0
	m.PreviewOnly = false
	return m
}
func beginInlinePreview(m InlineModel) (InlineModel, InlineEffect) {
	m.Revision++
	m.Busy = true
	m.Stage = "loading"
	m.Query = ""
	m.Selection = 0
	m.Offset = 0
	m.Plan = nil
	m.Result = nil
	m.Progress = ProgressEvent{}
	m.LastError = nil
	return m, inlineEffect(m, "preview")
}
