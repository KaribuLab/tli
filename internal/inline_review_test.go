package internal

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Migrated behavior regressions from the retired panel, not snapshot checks.
func TestInlineReviewConsentControls(t *testing.T) {
	for _, w := range []int{40, 56, 89, 96} {
		for h := 10; h <= 19; h++ {
			m := inlinePreview(t)
			m.Width = w
			m.Height = h
			m.Selection = 1
			f := RenderInlineActive(m, TerminalOptions{Interactive: true})
			text := strings.Join(f.Lines, "\n")
			_, effect := inlineKey(m, "enter")
			if effect.Kind == "scan" && (!f.ConsentVisible || !strings.Contains(text, "Volver") || !strings.Contains(text, "Enviar a Titvo")) {
				t.Fatal("invisible consent", w, h, text)
			}
		}
	}
}
func TestInlineReviewHumanControlInjection(t *testing.T) {
	attack := "git@host:repo\x1b]52;c;YQ==\a"
	p := ScanPlan{Repository: RepositoryIdentity{URL: attack}}
	r := StatusResult{ReportUrl: attack, Result: ScanResult{Annotations: []Annotation{{Title: attack, Code: attack}}}}
	var out bytes.Buffer
	WritePlan(&out, p, "markdown")
	if strings.ContainsAny(out.String(), "\x1b\a") {
		t.Fatal("human preview controls")
	}
	out.Reset()
	WriteResult(&out, r, "markdown", false)
	if strings.ContainsAny(out.String(), "\x1b\a") {
		t.Fatal("human result controls")
	}
	out.Reset()
	WriteResult(&out, r, "json", false)
	var raw StatusResult
	if e := json.Unmarshal(out.Bytes(), &raw); e != nil || raw.ReportUrl != attack || raw.Result.Annotations[0].Code != attack {
		t.Fatal("machine data changed", e)
	}
}
func TestInlineReviewCoverageContradiction(t *testing.T) {
	for _, missing := range []bool{false, true} {
		r := StatusResult{Result: ScanResult{Status: "COMPLETED", Coverage: &ScanCoverage{Complete: true}}}
		if missing {
			r.Result.Incomplete = &ScanIncomplete{Message: "missing"}
		} else {
			r.Result.Coverage.Errors = []string{"batch failed"}
		}
		text := RenderInlineOutcome(r, nil, TerminalOptions{})
		if !strings.Contains(text, "incompleta (reportada completa)") {
			t.Fatal(text)
		}
	}
}
func TestInlineReviewUnicodeDataInASCII(t *testing.T) {
	m := inlineFixture()
	m.Stage = "details"
	m.Identity.Branch = "feature/año"
	m.Result = &StatusResult{ReportUrl: "https://example.test/año", Result: ScanResult{Status: "WARNING", Annotations: []Annotation{{Title: "Revisión ñ", Path: "src/año.go", Code: `var texto = "sí"`}}}}
	c := TerminalOptions{ASCII: true, Interactive: true}
	text := strings.Join(RenderInlineActive(m, c).Lines, "\n")
	for _, s := range []string{"src/año.go", "sí", "Revisión ñ"} {
		if !strings.Contains(text, s) {
			t.Fatalf("external data changed %q", s)
		}
	}
	if !strings.Contains(RenderInlineOutcome(*m.Result, nil, c), m.Result.ReportUrl) || !strings.Contains(RenderInlineWelcome(m.Identity, nil, c), m.Identity.Branch) {
		t.Fatal("external metadata transliterated")
	}
}
func TestInlineReviewVisibleSelection(t *testing.T) {
	m := inlineFixture()
	m.WelcomeCommitted = true
	c := TerminalOptions{Interactive: true, ASCII: true}
	before := strings.Join(RenderInlineActive(m, c).Lines, "\n")
	m, e := inlineKey(m, "down")
	after := strings.Join(RenderInlineActive(m, c).Lines, "\n")
	if e.Kind != "" || before == after || !strings.Contains(after, "> Un commit") {
		t.Fatal("invisible keyboard selection")
	}
}
func TestInlineReviewStaleRegionRemoved(t *testing.T) {
	var out bytes.Buffer
	r := ownedInlineRegion{out: &out, width: 40, height: 12}
	r.begin(func() error { return nil })
	r.draw(InlineFrame{Lines: []string{"STALE-CONTROL", "OLD-RESULT", "query"}})
	r.draw(InlineFrame{Lines: []string{"fresh"}})
	r.end()
	vt := newOwnedVT(40, 12)
	vt.feed("SHELL-PREVIO\r\n")
	vt.feed(out.String())
	if strings.Contains(vt.text(), "STALE-CONTROL") || strings.Contains(vt.text(), "OLD-RESULT") || !strings.Contains(vt.text(), "SHELL-PREVIO") {
		t.Fatal(vt.text())
	}
}
