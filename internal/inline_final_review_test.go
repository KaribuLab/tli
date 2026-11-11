package internal

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInlineResizeRoundTripInvalidatesConsent(t *testing.T) {
	term := fakeInline()
	svc := &inlineServiceFixture{}
	_, done := startInlineTest(t, term, svc, nil)
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	term.keys <- "enter"
	waitInlineFrame(t, term, "¿Iniciar este análisis?")
	term.keys <- "down"
	term.resize(39, 9)
	term.resize(96, 28)
	term.keys <- "enter"
	waitInlineFrame(t, term, "Ajustando tamaño")
	term.keys <- "ctrl+c"
	waitInlineDone(t, done)
	if svc.scans.Load() != 0 {
		t.Fatal("unobserved roundtrip submitted")
	}
}
func TestInlineResizeDrainPreservesControlKeys(t *testing.T) {
	for _, path := range []string{"reader", "drain"} {
		for _, key := range []string{"ctrl+c", "eof", "esc"} {
			t.Run(path+"/"+key, func(t *testing.T) {
				term := fakeInline()
				svc := &inlineServiceFixture{}
				ticks := make(chan time.Time)
				var clock atomic.Int64
				_, done := startInlineTest(t, term, svc, func(s *InlineSession) {
					s.ResizeTicks = ticks
					s.Now = func() time.Time { return time.Unix(0, clock.Load()) }
				})
				runInlineScan(t, term)
				term.resize(50, 14)
				ticks <- time.Now()
				waitInlineFrame(t, term, "Ajustando tamaño")
				term.mu.Lock()
				if path == "drain" {
					term.onDiscard = func() { term.keys <- key }
				} else {
					term.onSize = func() {
						term.keys <- key
						timer := time.NewTimer(time.Second)
						defer timer.Stop()
						for {
							select {
							case read := <-term.notices:
								if read == key {
									return
								}
							case <-timer.C:
								t.Error("reader did not acknowledge control")
								return
							}
						}
					}
				}
				term.mu.Unlock()
				clock.Store(int64(300 * time.Millisecond))
				ticks <- time.Now()
				if key == "esc" {
					waitInlineFrame(t, term, "¿Qué quieres hacer ahora?")
					term.keys <- "esc"
					waitInlineFrame(t, term, "¿Qué quieres revisar?")
					term.keys <- "esc"
				}
				e := waitInlineDone(t, done)
				if key == "ctrl+c" && !errors.Is(e, context.Canceled) {
					t.Fatal(e)
				}
				if key != "ctrl+c" && e != nil {
					t.Fatal(e)
				}
				if svc.active.Load() != 0 || !strings.Contains(term.transcript(), "scan-fixture") {
					t.Fatal("cancel did not preserve cleanup/identity")
				}
			})
		}
	}
}
func TestInlineUnterminatedOSCDoesNotConsumeLaterMetadata(t *testing.T) {
	r := StatusResult{ScanID: "scan-fixture", ReportUrl: "https://example.test/report", Result: ScanResult{Status: "WARNING", NumberOfIssues: 1, Annotations: []Annotation{{Title: "\x1b]52;c;payload", Path: "source.go", Line: 9}}}}
	text := RenderInlineOutcome(r, nil, TerminalOptions{})
	if !strings.Contains(text, "scan_id: scan-fixture") || !strings.Contains(text, r.ReportUrl) || !strings.Contains(text, "source.go") {
		t.Fatalf("metadata swallowed %q", text)
	}
	if r.Result.Annotations[0].Title != "\x1b]52;c;payload" {
		t.Fatal("DTO changed")
	}
}
func TestInlineASCIIOwnedPunctuation(t *testing.T) {
	m := inlinePreview(t)
	c := TerminalOptions{Interactive: true, ASCII: true}
	for _, stage := range []string{"actions", "scope", "commit", "confirm", "files", "running", "result-actions"} {
		m.Stage = stage
		for _, line := range RenderInlineActive(m, c).Lines {
			for _, r := range line {
				if r > 127 {
					t.Fatalf("stage%s non-ascii UI %q", stage, r)
				}
			}
		}
	}
}
