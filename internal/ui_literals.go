package internal

import "strings"

// Transliterate only UI-owned labels. Callers must not pass paths, source or URLs.
func uiText(s string, ascii bool) string {
	if !ascii {
		return s
	}
	return strings.NewReplacer("á", "a", "é", "e", "í", "i", "ó", "o", "ú", "u", "ñ", "n", "Á", "A", "É", "E", "Í", "I", "Ó", "O", "Ú", "U", "Ñ", "N", "¿", "", "¡", "", "×", "x", "↑", "^", "↓", "v", "→", ">", "·", "|", "›", ">", "✓", "+", "─", "-", "│", "|").Replace(s)
}
func scopeLabel(scope ScanScope) string {
	switch scope {
	case ScopeCommit:
		return "Commit"
	case ScopeStaged:
		return "Staged"
	default:
		return "Completo"
	}
}
