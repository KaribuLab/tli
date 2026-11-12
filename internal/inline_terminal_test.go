package internal

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Independent ASCII terminal model for the relative cursor/erase subset. It
// retains scrollback so an upward overwrite of shell/committed data is observable.
type ownedVT struct {
	lines       [][]rune
	history     []string
	row, col, w int
}

func newOwnedVT(w, h int) *ownedVT {
	v := &ownedVT{w: w}
	for i := 0; i < h; i++ {
		v.lines = append(v.lines, []rune(strings.Repeat(" ", w)))
	}
	return v
}
func (v *ownedVT) down() {
	v.row++
	if v.row >= len(v.lines) {
		v.history = append(v.history, string(v.lines[0]))
		v.lines = append(v.lines[1:], []rune(strings.Repeat(" ", v.w)))
		v.row = len(v.lines) - 1
	}
}
func (v *ownedVT) feed(s string) {
	pattern := regexp.MustCompile(`^\x1b\[([0-9;?]*)([A-Za-z])`)
	for len(s) > 0 {
		if m := pattern.FindStringSubmatch(s); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n == 0 {
				n = 1
			}
			switch m[2] {
			case "A":
				v.row = max(0, v.row-n)
			case "B":
				v.row = min(len(v.lines)-1, v.row+n)
			case "K":
				for i := range v.lines[v.row] {
					v.lines[v.row][i] = ' '
				}
			case "H":
				v.row = 0
				v.col = 0
			case "J":
				for r := range v.lines {
					for c := range v.lines[r] {
						v.lines[r][c] = ' '
					}
				}
			}
			s = s[len(m[0]):]
			continue
		}
		b := rune(s[0])
		s = s[1:]
		switch b {
		case '\r':
			v.col = 0
		case '\n':
			v.down()
		default:
			if v.col >= v.w {
				v.col = 0
				v.down()
			}
			v.lines[v.row][v.col] = b
			v.col++
		}
	}
}
func (v *ownedVT) text() string {
	parts := append([]string{}, v.history...)
	for _, line := range v.lines {
		parts = append(parts, string(line))
	}
	return strings.Join(parts, "\n")
}
func TestInlineTerminalPreservesShellPrefix(t *testing.T) {
	var out bytes.Buffer
	r := ownedInlineRegion{out: &out, width: 40, height: 12}
	r.begin(func() error { return nil })
	r.draw(InlineFrame{Lines: []string{"old1", "old2", "query"}})
	r.draw(InlineFrame{Lines: []string{"short"}})
	r.commit("REPORT-CONFIRMED")
	r.draw(InlineFrame{Lines: []string{"new action", "> "}})
	r.end()
	vt := newOwnedVT(40, 12)
	vt.feed("SHELL-PREVIO\r\n")
	vt.feed(out.String())
	text := vt.text()
	if !strings.HasPrefix(text, "SHELL-PREVIO") || !strings.Contains(text, "REPORT-CONFIRMED") || strings.Contains(text, "old1") || strings.Contains(text, "old2") {
		t.Fatal(text)
	}
}
func TestInlineTerminalNeverUsesGlobalClear(t *testing.T) {
	var out bytes.Buffer
	r := ownedInlineRegion{out: &out, width: 40, height: 12}
	r.begin(func() error { return nil })
	r.draw(InlineFrame{Lines: []string{"one", "two"}})
	r.draw(InlineFrame{Lines: []string{"three"}})
	r.end()
	for _, bad := range []string{"\x1b[?1049", "\x1b[2J", "\x1b[3J", "\x1b[H", ";1H"} {
		if strings.Contains(out.String(), bad) {
			t.Fatalf("global control %q", bad)
		}
	}
}
func TestInlineTerminalRowsDoNotWrap(t *testing.T) {
	var out bytes.Buffer
	r := ownedInlineRegion{out: &out, width: 40, height: 12}
	r.begin(func() error { return nil })
	if e := r.draw(InlineFrame{Lines: []string{strings.Repeat("界", 19), "> e\u0301"}, CursorVisible: true}); e != nil {
		t.Fatal(e)
	}
	if e := r.draw(InlineFrame{Lines: []string{strings.Repeat("界", 20)}}); e == nil {
		t.Fatal("wrapping row accepted")
	}
}
func TestInlineTerminalAbandonsUnknownGeometry(t *testing.T) {
	var out bytes.Buffer
	r := ownedInlineRegion{out: &out, width: 40, height: 12}
	r.begin(func() error { return nil })
	r.draw(InlineFrame{Lines: []string{"old", "query"}})
	out.Reset()
	r.abandon("Vista anulada por resize")
	if strings.Contains(out.String(), "\x1b[") || r.rows != 0 || !strings.Contains(out.String(), "Vista anulada") {
		t.Fatalf("unsafe uncertain redraw %q", out.String())
	}
}

type ownedFailWriter struct {
	bytes.Buffer
	fail bool
}

func (w *ownedFailWriter) Write(b []byte) (int, error) {
	if w.fail {
		w.fail = false
		return 0, errors.New("fixture writer failure")
	}
	return w.Buffer.Write(b)
}
func (w *ownedFailWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }
func TestInlineTerminalWriteFailureRestores(t *testing.T) {
	out := &ownedFailWriter{}
	restores := 0
	r := ownedInlineRegion{out: out, width: 40, height: 12}
	r.begin(func() error { restores++; return nil })
	out.fail = true
	if e := r.draw(InlineFrame{Lines: []string{"failed"}}); e == nil {
		t.Fatal("write error lost")
	}
	if restores != 1 {
		t.Fatalf("restore=%d", restores)
	}
}
func TestInlineTerminalEndIdempotent(t *testing.T) {
	var out bytes.Buffer
	restores := 0
	r := ownedInlineRegion{out: &out, width: 40, height: 12}
	r.begin(func() error { restores++; return nil })
	r.end()
	first := out.String()
	r.end()
	if restores != 1 || out.String() != first || !strings.HasSuffix(first, "\r\n") {
		t.Fatal("bad terminal cleanup")
	}
}
