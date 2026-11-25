package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestSafeTerminalTextCannotExecuteControls(t *testing.T) {
	for _, raw := range []string{"a\x1b]52;c;payload\a.go", "a\x1b[2Jb", "a\x1b]8;;https://evil.test\x1b\\b", "a\r\bb\x00", "a\u009b2Jb"} {
		safe := SafeTerminalText(raw)
		if strings.ContainsAny(safe, "\x1b\a\r\b\x00\u009b") {
			t.Fatalf("unsafe text %q", safe)
		}
		data, _ := json.Marshal(raw)
		var decoded string
		json.Unmarshal(data, &decoded)
		if decoded != raw {
			t.Fatal("machine data changed")
		}
	}
	if s := SafeTerminalText("a\tb\nc"); s != "a    b\nc" {
		t.Fatalf("whitespace=%q", s)
	}
}
func TestCellWidthAndWrap(t *testing.T) {
	for _, tc := range []struct {
		s    string
		want int
	}{{"hello", 5}, {"A界e\u0301", 4}, {" ▄▟██▙▄", 7}, {"niño", 4}} {
		if got := CellWidth(tc.s); got != tc.want {
			t.Fatalf("width(%q)=%d want%d", tc.s, got, tc.want)
		}
	}
	for _, line := range WrapCells("A界e\u0301xx\nsegunda", 4) {
		if !utf8.ValidString(line) || CellWidth(line) > 4 {
			t.Fatalf("bad wrap %q", line)
		}
	}
	if got := ClipCells("界界", 3); got != "界" {
		t.Fatalf("partial cell clip %q", got)
	}
	if got := ClipCells("a\nb", 10); got != "a\\nb" {
		t.Fatalf("line injection %q", got)
	}
}
func TestMarkdownIncludesCoverageErrors(t *testing.T) {
	r := terminalFixture("COMPLETED").Result
	r.Result.Coverage = &ScanCoverage{Errors: []string{"batch missing", "decode failure"}}
	var out bytes.Buffer
	if e := WriteResult(&out, r, "markdown", false); e != nil {
		t.Fatal(e)
	}
	for _, cause := range r.Result.Coverage.Errors {
		if !strings.Contains(out.String(), cause) {
			t.Fatalf("missing %q", cause)
		}
	}
}
func TestRedirectedProgressHasNoANSI(t *testing.T) {
	var out bytes.Buffer
	sink, finish := progressSession(context.Background(), &out, TerminalOptions{Interactive: true, Animate: true, Color: true}, nil, func() time.Time { return time.Unix(0, 0) })
	sink(ProgressEvent{Phase: "analyzing", ScanID: "fixture"})
	finish()
	if strings.Contains(out.String(), "\x1b") {
		t.Fatalf("redirected output contains controls %q", out.String())
	}
}
