package internal

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func envFixture(values map[string]string) func(string) string {
	return func(k string) string { return values[k] }
}
func TestTerminalNonInteractiveMatrix(t *testing.T) {
	for _, tc := range []struct {
		in, out bool
		env     map[string]string
		want    bool
	}{
		{true, true, map[string]string{}, true}, {false, true, nil, false}, {true, false, nil, false},
		{true, true, map[string]string{"CI": "true"}, false}, {true, true, map[string]string{"CI": "1"}, false}, {true, true, map[string]string{"CI": "false"}, true},
		{true, true, map[string]string{"GITHUB_ACTIONS": "true"}, false}, {true, true, map[string]string{"BITBUCKET_BUILD_NUMBER": "600"}, false}, {true, true, map[string]string{"TERM": "dumb"}, false},
	} {
		got := terminalOptions(tc.in, tc.out, envFixture(tc.env))
		if got.Interactive != tc.want {
			t.Fatalf("%+v => %+v", tc, got)
		}
	}
}
func TestTerminalNoColorAndReducedMotion(t *testing.T) {
	for _, env := range []map[string]string{{"NO_COLOR": "1"}, {"TLI_NO_ANIMATION": "1"}} {
		o := terminalOptions(true, true, envFixture(env))
		if o.Animate {
			t.Fatal("motion ignored")
		}
		if env["NO_COLOR"] != "" && o.Color {
			t.Fatal("NO_COLOR ignored")
		}
	}
}
func TestMascotFrames(t *testing.T) {
	var out bytes.Buffer
	for frame := 0; frame < 4; frame++ {
		out.Reset()
		if e := WriteMascot(&out, TerminalOptions{Interactive: true}, frame); e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(out.String(), "▄▟██▙▄") || strings.Contains(out.String(), "\x1b") {
			t.Fatal(out.String())
		}
		if len(strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")) != 4 {
			t.Fatal("mascot must have 4 lines")
		}
	}
}
func TestMascotASCII(t *testing.T) {
	var out bytes.Buffer
	WriteMascot(&out, TerminalOptions{Interactive: true, ASCII: true}, 0)
	for _, r := range out.String() {
		if r > 127 {
			t.Fatal("non-ASCII mascot")
		}
	}
}
func TestNonInteractiveWritesNoMascot(t *testing.T) {
	var out bytes.Buffer
	if e := WriteMascot(&out, TerminalOptions{}, 0); e != nil {
		t.Fatal(e)
	}
	if out.Len() != 0 {
		t.Fatal(out.String())
	}
}
func TestProgressNeverInventsPercent(t *testing.T) {
	for _, animate := range []bool{false, true} {
		var out bytes.Buffer
		e := WriteProgress(&out, TerminalOptions{Interactive: true, Animate: animate}, ProgressEvent{Phase: "analyzing", ScanID: "scan-fixture", Files: 3, Bytes: 77, Elapsed: 8 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		for _, word := range []string{"scan-fixture", "3", "77"} {
			if !strings.Contains(out.String(), word) {
				t.Fatalf("missing real counter %q", word)
			}
		}
		if strings.ContainsAny(out.String(), "%$") {
			t.Fatal("invented progress")
		}
	}
}
