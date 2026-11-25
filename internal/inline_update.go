package internal

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"
)

func UpdateInline(m InlineModel, e InlineEvent) (next InlineModel, effect InlineEffect) {
	defer func() { next = clampInline(next) }()
	none := InlineEffect{}
	switch e.Kind {
	case "resize":
		m.Width = max(0, e.Width)
		m.Height = max(0, e.Height)
		m.GeometryReady = false
		if m.Stage == "confirm" {
			m.Selection = 0
		}
		return m, none
	case "geometry-ready":
		m.Width = max(0, e.Width)
		m.Height = max(0, e.Height)
		m.GeometryReady = m.Width >= 40 && m.Height >= 10
		return m, none
	case "tick":
		m.MotionTick++
		if m.Busy && m.Stage == "running" {
			m.Progress.Elapsed = e.Elapsed
		}
		return m, none
	}
	if e.Kind != "key" {
		if e.Revision != m.Revision || !m.Busy {
			return m, none
		}
		switch e.Kind {
		case "progress":
			if e.Progress.Files == 0 {
				e.Progress.Files = m.Progress.Files
				e.Progress.Bytes = m.Progress.Bytes
			}
			m.Progress = e.Progress
		case "preview-done":
			m.Busy = false
			m.LastError = e.Err
			if m.ExitRequested {
				return m, inlineEffect(m, "exit")
			}
			if e.Err != nil || e.Plan == nil {
				return inlineHome(m), none
			}
			m.Plan = e.Plan
			m.Selection = 0
			m.Offset = 0
			m.Stage = "confirm"
			if m.PreviewOnly {
				m.Stage = "files"
			}
		case "scan-done":
			m.Busy = false
			m.LastError = e.Err
			if e.Result != nil {
				r := *e.Result
				if r.ScanID == "" {
					r.ScanID = m.Progress.ScanID
				}
				m.Result = &r
			} else if m.Progress.ScanID != "" {
				m.Result = &StatusResult{ScanID: m.Progress.ScanID}
			}
			if m.ExitRequested {
				return m, inlineEffect(m, "exit")
			}
			var se *ScanError
			if errors.As(e.Err, &se) && se.Kind == "plan-changed" {
				return beginInlinePreview(m)
			}
			m.Stage = "result-actions"
			m.Query = ""
			m.Selection = 0
			m.Offset = 0
		case "setup-done":
			m.Busy = false
			m.LastError = e.Err
			m = inlineHome(m)
			if errors.Is(e.Err, context.Canceled) {
				m.Interrupted = true
				return m, inlineEffect(m, "exit")
			}
		}
		return m, none
	}
	key := e.Key
	if m.Busy {
		if key == "ctrl+c" || key == "esc" {
			m.ExitRequested = key == "ctrl+c"
			m.Interrupted = key == "ctrl+c"
			return m, inlineEffect(m, "cancel")
		}
		return m, none
	}
	if key == "ctrl+c" {
		m.Interrupted = true
		return m, inlineEffect(m, "exit")
	}
	if key == "esc" {
		if inlineSearchStage(m) && m.Query != "" {
			m.Query = ""
			m.Selection = 0
			return m, none
		}
		switch m.Stage {
		case "actions":
			return m, inlineEffect(m, "exit")
		case "files":
			m.Selection = 0
			m.Offset = 0
			if m.PreviewOnly {
				return inlineHome(m), none
			}
			m.Stage = "confirm"
		case "details", "coverage":
			m.Stage = "result-actions"
			m.Query = ""
			m.Selection = 0
			m.Offset = 0
		default:
			m = inlineHome(m)
		}
		return m, none
	}
	if key == "enter" && !m.GeometryReady {
		return m, none
	}
	if m.Stage == "commit" {
		switch key {
		case "enter":
			if strings.TrimSpace(m.DraftCommit) == "" {
				return m, none
			}
			m.Options.Scope = ScopeCommit
			m.Options.Commit = m.DraftCommit
			return beginInlinePreview(m)
		case "backspace":
			if len(m.DraftCommit) > 0 {
				_, n := utf8.DecodeLastRuneInString(m.DraftCommit)
				m.DraftCommit = m.DraftCommit[:len(m.DraftCommit)-n]
			}
		default:
			if utf8.RuneCountInString(key) == 1 && len(m.DraftCommit)+len(key) <= 512 {
				m.DraftCommit += key
			}
		}
		return m, none
	}
	delta := 0
	switch key {
	case "up", "left":
		delta = -1
	case "down", "right":
		delta = 1
	}
	if m.Stage == "files" || m.Stage == "details" || m.Stage == "coverage" {
		if key == "j" {
			delta = 1
		}
		if key == "k" {
			delta = -1
		}
		if m.Stage == "files" && m.Plan != nil {
			if key == "tab" {
				if m.ListKind == "incluidos" {
					m.ListKind = "excluidos"
				} else {
					m.ListKind = "incluidos"
				}
				m.Selection = 0
			}
			n := len(m.Plan.Files)
			if m.ListKind == "excluidos" {
				n = len(m.Plan.Excluded)
			}
			m.Selection = max(0, min(max(0, n-1), m.Selection+delta))
		} else if m.Stage == "details" && m.Result != nil {
			m.Selection = max(0, min(max(0, len(m.Result.Result.Annotations)-1), m.Selection+delta))
			if delta != 0 {
				m.Offset = 0
			}
		} else {
			m.Offset = max(0, m.Offset+delta)
		}
		if key == "pagedown" {
			m.Offset += max(1, m.Height/2)
		}
		if key == "pageup" {
			m.Offset = max(0, m.Offset-max(1, m.Height/2))
		}
		return m, none
	}
	if inlineSearchStage(m) {
		if key == "backspace" {
			if len(m.Query) > 0 {
				_, n := utf8.DecodeLastRuneInString(m.Query)
				m.Query = m.Query[:len(m.Query)-n]
			}
			m.Selection = 0
		} else if utf8.RuneCountInString(key) == 1 && len(m.Query)+len(key) <= 512 {
			m.Query += key
			m.Selection = 0
		}
	}
	choices := inlineChoices(m)
	if len(choices) == 0 {
		m.Selection = 0
		return m, none
	}
	m.Selection = max(0, min(len(choices)-1, m.Selection+delta))
	if key != "enter" {
		return m, none
	}
	id := choices[m.Selection].ID
	switch id {
	case "quit":
		return m, inlineEffect(m, "exit")
	case "new", "back":
		return inlineHome(m), none
	case "preview":
		m.Stage = "scope"
		m.PreviewOnly = true
		m.Query = ""
		m.Selection = 0
	case "setup":
		m.Busy = true
		m.Revision++
		m.Query = ""
		return m, inlineEffect(m, "setup")
	case "staged", "commit", "full":
		if m.IdentityError != nil {
			m.LastError = m.IdentityError
			return m, none
		}
		m.Options.Commit = ""
		if id == "commit" {
			m.Stage = "commit"
			m.Query = ""
			return m, none
		}
		m.Options.Scope = ScopeStaged
		if id == "full" {
			m.Options.Scope = ScopeFull
		}
		return beginInlinePreview(m)
	case "files":
		m.Stage = "files"
		m.ListKind = "incluidos"
		m.Selection = 0
		m.Offset = 0
	case "details", "coverage":
		m.Stage = id
		m.Selection = 0
		m.Offset = 0
		m.Query = ""
	case "send":
		if InlineConsentVisible(m) {
			m.Revision++
			m.Busy = true
			m.Stage = "running"
			m.Progress = ProgressEvent{Phase: "preparing", Files: len(m.Plan.Files), Bytes: m.Plan.TotalBytes}
			return m, inlineEffect(m, "scan")
		}
		return m, none
	}
	return m, none
}
