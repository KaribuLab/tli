package internal

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestInlineFrameBoundsAndConsent(t *testing.T) {
	for _, size := range [][2]int{{40, 10}, {56, 16}, {96, 28}, {39, 9}} {
		m := inlinePreview(t)
		m.Width = size[0]
		m.Height = size[1]
		m.Selection = 1
		f := RenderInlineActive(m, TerminalOptions{Interactive: true})
		if len(f.Lines) > m.Height-2 {
			t.Fatal("overflow rows")
		}
		for _, line := range f.Lines {
			if CellWidth(line) > m.Width-1 || strings.Contains(line, "\x1b") {
				t.Fatalf("unsafe line %q", line)
			}
		}
		_, effect := inlineKey(m, "enter")
		if effect.Kind == "scan" && (!f.ConsentVisible || !strings.Contains(strings.Join(f.Lines, " "), "Volver")) {
			t.Fatal("hidden consent")
		}
		if size[0] >= 40 && size[1] >= 10 && !f.ConsentVisible {
			t.Fatalf("consent unexpectedly missing at%v: %v", size, f.Lines)
		}
	}
}
func TestInlineQueryAndEmptyState(t *testing.T) {
	m := inlineFixture()
	m.Query = "xxxxxxxxxx"
	f := RenderInlineActive(m, TerminalOptions{Interactive: true})
	if !strings.Contains(strings.Join(f.Lines, " "), "Sin coincidencias") {
		t.Fatal(f)
	}
	if !strings.Contains(f.Lines[len(f.Lines)-1], m.Query) {
		t.Fatal("query not last row")
	}
	m.WelcomeCommitted = true
	m.Width = 40
	m.Query = strings.Repeat("界", 100)
	f = RenderInlineActive(m, TerminalOptions{Interactive: true})
	for _, line := range f.Lines {
		if CellWidth(line) > 39 {
			t.Fatal("wide input overflow")
		}
	}
}
func TestInlineExplicitSendUsesMeasuredConsent(t *testing.T) {
	m := inlinePreview(t)
	m.Selection = 1
	_, e := inlineKey(m, "enter")
	if e.Kind != "scan" || e.Fingerprint != "exact" {
		t.Fatal("measured consent not used", e)
	}
}
func TestInlineEmptyShortFrameKeepsInputLast(t *testing.T) {
	m := inlineFixture()
	m.Width = 40
	m.Height = 10
	m.Query = "zzxy"
	f := RenderInlineActive(m, TerminalOptions{Interactive: true})
	if !strings.Contains(f.Lines[len(f.Lines)-1], m.Query) {
		t.Fatal("input was clipped", f.Lines)
	}
}
func TestInlineFrameWithoutPlan(t *testing.T) {
	m := inlineFixture()
	m.Stage = "confirm"
	f := RenderInlineActive(m, TerminalOptions{Interactive: true})
	if f.ConsentVisible {
		t.Fatal("nil plan consents")
	}
}
func TestInlinePreviewSamples(t *testing.T) {
	p := ScanPlan{Files: make([]PlannedFile, 10), Excluded: make([]ExcludedFile, 8)}
	for i := range p.Files {
		p.Files[i].Path = fmt.Sprintf("include-%d.go", i)
	}
	for i := range p.Excluded {
		p.Excluded[i] = ExcludedFile{Path: fmt.Sprintf("exclude-%d", i), Reason: "binary"}
	}
	text := RenderInlinePreview(p, TerminalOptions{})
	if strings.Count(text, "include-") != 5 || strings.Count(text, "exclude-") != 3 || !strings.Contains(text, "10 incluidos") || !strings.Contains(text, "8 excluidos") {
		t.Fatal(text)
	}
}
func TestInlineOutcomeNoInventedDetails(t *testing.T) {
	r := StatusResult{ScanID: "fixture", Result: ScanResult{Status: "FAILED", NumberOfIssues: 12, Coverage: &ScanCoverage{Complete: true, Errors: []string{"batch missing"}}}}
	text := RenderInlineOutcome(r, nil, TerminalOptions{})
	if !strings.Contains(text, "12 reportados") || !strings.Contains(text, "no se recibieron") || !strings.Contains(text, "incompleta") || !strings.Contains(text, "batch missing") {
		t.Fatal(text)
	}
	text = RenderInlineOutcome(StatusResult{ScanID: "running"}, errors.New("cancelled"), TerminalOptions{})
	if strings.Contains(text, "0 reportados") || !strings.Contains(text, "running") {
		t.Fatal(text)
	}
}
func TestInlineASCIIAndInjection(t *testing.T) {
	m := inlineFixture()
	m.Stage = "details"
	m.Result = &StatusResult{ReportUrl: "https://example.test/año", Result: ScanResult{Annotations: []Annotation{{Title: "Revisión", Path: "src/año.go", Code: `var texto = "sí"` + "\x1b]52;evil\a"}}}}
	text := strings.Join(RenderInlineActive(m, TerminalOptions{Interactive: true, ASCII: true}).Lines, "\n")
	if strings.ContainsAny(text, "\x1b\a") || !strings.Contains(text, "src/año.go") || !strings.Contains(text, "sí") {
		t.Fatal(text)
	}
}

type blockRecorder struct {
	blocks []string
	fail   bool
}

func (r *blockRecorder) CommitBlock(s string) error {
	if r.fail {
		return errors.New("fixture write")
	}
	r.blocks = append(r.blocks, s)
	return nil
}
func TestInlineCommitOnce(t *testing.T) {
	r := &blockRecorder{}
	tx := Transcript{Terminal: r}
	if e := tx.CommitOnce("welcome", "first"); e != nil {
		t.Fatal(e)
	}
	tx.CommitOnce("welcome", "duplicate")
	if len(r.blocks) != 1 {
		t.Fatal(r.blocks)
	}
	r.fail = true
	if e := tx.CommitOnce("result", "result"); e == nil {
		t.Fatal("write failure swallowed")
	}
	r.fail = false
	tx.CommitOnce("result", "result")
	if len(r.blocks) != 2 {
		t.Fatal("failed key was consumed")
	}
}
func TestInlineMotionOnlyTouchesActiveFrame(t *testing.T) {
	m := inlineFixture()
	caps := TerminalOptions{Interactive: true, Animate: true}
	before := RenderInlineActive(m, caps)
	m, _ = UpdateInline(m, InlineEvent{Kind: "tick", Elapsed: 500 * time.Millisecond})
	m.MotionTick = 7
	after := RenderInlineActive(m, caps)
	if strings.Join(before.Lines, "") == strings.Join(after.Lines, "") {
		t.Fatal("idle welcome does not blink")
	}
	m.WelcomeCommitted = true
	first := RenderInlineActive(m, caps)
	m.MotionTick++
	second := RenderInlineActive(m, caps)
	if strings.Join(first.Lines, "") != strings.Join(second.Lines, "") {
		t.Fatal("committed welcome was animated")
	}
	m.Stage = "running"
	m.Progress = ProgressEvent{Phase: "analyzing", Files: 3, Bytes: 99}
	a := RenderInlineActive(m, caps)
	m, _ = UpdateInline(m, InlineEvent{Kind: "tick", Elapsed: time.Second})
	b := RenderInlineActive(m, caps)
	if strings.Join(a.Lines, "") == strings.Join(b.Lines, "") || m.Progress.Files != 3 || m.Progress.Bytes != 99 {
		t.Fatal("motion/data contract")
	}
}
