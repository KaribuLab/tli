package internal

import (
	"strings"
	"unicode"

	"golang.org/x/text/width"
)

// Only printable text, LF and expanded tabs survive. Escape-string payloads are
// consumed, never forwarded to a terminal (including OSC clipboard/hyperlinks).
func SafeTerminalText(text string) string {
	runes := []rune(text)
	var out strings.Builder
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == 27 || r == 0x9b || r == 0x9d || r == 0x90 {
			kind := r
			if r == 27 {
				i++
				if i >= len(runes) {
					break
				}
				kind = runes[i]
			}
			if kind == '[' || kind == 0x9b {
				for i++; i < len(runes); i++ {
					if runes[i] >= 0x40 && runes[i] <= 0x7e {
						break
					}
				}
				continue
			}
			if kind == ']' || kind == 'P' || kind == 'X' || kind == '^' || kind == '_' || kind == 0x9d || kind == 0x90 {
				for i++; i < len(runes); i++ {
					if runes[i] == 7 || runes[i] == 0x9c {
						break
					}
					if runes[i] == 27 && i+1 < len(runes) && runes[i+1] == '\\' {
						i++
						break
					}
				}
				continue
			}
			continue
		}
		switch r {
		case '\n':
			out.WriteRune(r)
		case '\t':
			out.WriteString("    ")
		default:
			if !unicode.IsControl(r) && !unicode.Is(unicode.Cf, r) {
				out.WriteRune(r)
			}
		}
	}
	return out.String()
}
func runeCells(r rune) int {
	if unicode.IsControl(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r) {
		return 0
	}
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2
	}
	return 1
}
func CellWidth(text string) int {
	n := 0
	for _, r := range text {
		n += runeCells(r)
	}
	return n
}
func ClipCells(text string, max int) string {
	if max <= 0 {
		return ""
	}
	text = strings.ReplaceAll(SafeTerminalText(text), "\n", "\\n")
	var out strings.Builder
	n := 0
	for _, r := range text {
		w := runeCells(r)
		if n+w > max {
			break
		}
		out.WriteRune(r)
		n += w
	}
	return out.String()
}
func WrapCells(text string, max int) []string {
	if max <= 0 {
		return nil
	}
	var lines []string
	for _, part := range strings.Split(SafeTerminalText(text), "\n") {
		var line strings.Builder
		n := 0
		for _, r := range part {
			w := runeCells(r)
			if w > max {
				r = '?'
				w = 1
			}
			if n+w > max {
				lines = append(lines, line.String())
				line.Reset()
				n = 0
			}
			line.WriteRune(r)
			n += w
		}
		lines = append(lines, line.String())
	}
	return lines
}
