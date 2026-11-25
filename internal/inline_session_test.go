package internal

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeInlineTerminal struct {
	mu                   sync.Mutex
	keys                 chan string
	frames               chan string
	blocks               []string
	w, h                 int
	active               bool
	abandoned, discarded int
	readers, maxReaders  atomic.Int32
	epoch                atomic.Uint64
	onDiscard, onSize    func()
	notices              chan string
}

func fakeInline() *fakeInlineTerminal {
	return &fakeInlineTerminal{keys: make(chan string, 64), frames: make(chan string, 256), w: 96, h: 28, notices: make(chan string, 64)}
}
func (t *fakeInlineTerminal) Begin() error { t.mu.Lock(); t.active = true; t.mu.Unlock(); return nil }
func (t *fakeInlineTerminal) End() error   { t.mu.Lock(); t.active = false; t.mu.Unlock(); return nil }
func (t *fakeInlineTerminal) Size() (int, int, error) {
	t.mu.Lock()
	w, h, hook := t.w, t.h, t.onSize
	t.onSize = nil
	t.mu.Unlock()
	if hook != nil {
		hook()
	}
	return w, h, nil
}
func (t *fakeInlineTerminal) ReadKey(ctx context.Context) (string, error) {
	n := t.readers.Add(1)
	if n > t.maxReaders.Load() {
		t.maxReaders.Store(n)
	}
	defer t.readers.Add(-1)
	select {
	case key, ok := <-t.keys:
		if !ok {
			return "", io.EOF
		}
		select {
		case t.notices <- key:
		default:
		}
		return key, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
func (t *fakeInlineTerminal) DrawActive(f InlineFrame) error {
	select {
	case t.frames <- strings.Join(f.Lines, "\n"):
	default:
	}
	return nil
}
func (t *fakeInlineTerminal) CommitBlock(s string) error {
	t.mu.Lock()
	t.blocks = append(t.blocks, s)
	t.mu.Unlock()
	return nil
}
func (t *fakeInlineTerminal) AbandonActive(s string) error {
	t.mu.Lock()
	t.abandoned++
	t.mu.Unlock()
	return nil
}
func (t *fakeInlineTerminal) DiscardInput(context.Context) (string, error) {
	t.mu.Lock()
	t.discarded++
	hook := t.onDiscard
	t.onDiscard = nil
	t.mu.Unlock()
	if hook != nil {
		hook()
	}
	for {
		select {
		case key := <-t.keys:
			if inlineControl(key) != "" {
				return key, nil
			}
		default:
			return "", nil
		}
	}
}
func (t *fakeInlineTerminal) ResizeEpoch() uint64 { return t.epoch.Load() }
func (t *fakeInlineTerminal) resize(w, h int) {
	t.mu.Lock()
	t.w = w
	t.h = h
	t.epoch.Add(1)
	t.mu.Unlock()
}
func (t *fakeInlineTerminal) transcript() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.blocks, "\n")
}

type inlineServiceFixture struct {
	scans, active atomic.Int32
	onScan        func(context.Context, ProgressSink) (StatusResult, error)
}

func (s *inlineServiceFixture) Preview(ctx context.Context, o ScanOptions) (ScanPlan, error) {
	return ScanPlan{Files: []PlannedFile{{Path: "main.go", Size: 3}}, Scope: o.Scope, TotalBytes: 3, Fingerprint: "exact"}, nil
}
func (s *inlineServiceFixture) Scan(ctx context.Context, o ScanOptions, fp string, p ProgressSink) (StatusResult, error) {
	if fp != "exact" {
		return StatusResult{}, errors.New("bad fingerprint")
	}
	s.scans.Add(1)
	s.active.Add(1)
	defer s.active.Add(-1)
	p(ProgressEvent{Phase: "analyzing", ScanID: "scan-fixture", Files: 1, Bytes: 3})
	if s.onScan != nil {
		return s.onScan(ctx, p)
	}
	<-ctx.Done()
	return StatusResult{ScanID: "scan-fixture"}, ctx.Err()
}
func startInlineTest(t *testing.T, term *fakeInlineTerminal, svc *inlineServiceFixture, configure func(*InlineSession)) (*InlineSession, <-chan error) {
	t.Helper()
	s := &InlineSession{Terminal: term, Service: svc, Options: ScanOptions{Path: ".", Limits: DefaultLimits()}, Identity: RepositoryIdentity{Root: "demo", Branch: "main"}, Caps: TerminalOptions{Interactive: true}, Ticks: make(chan time.Time), ResizeTicks: make(chan time.Time)}
	if configure != nil {
		configure(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("inline session leaked")
		}
	})
	return s, done
}
func waitInlineFrame(t *testing.T, term *fakeInlineTerminal, want string) string {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case f := <-term.frames:
			if strings.Contains(f, want) {
				return f
			}
		case <-timer.C:
			t.Fatalf("inline frame not reached %s", want)
			return ""
		}
	}
}
func waitInlineDone(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case e := <-done:
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("inline exit blocked")
		return nil
	}
}
func runInlineScan(t *testing.T, term *fakeInlineTerminal) {
	t.Helper()
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	term.keys <- "enter"
	waitInlineFrame(t, term, "¿Iniciar este análisis?")
	term.keys <- "down"
	term.keys <- "enter"
	waitInlineFrame(t, term, "Esperando resultado del análisis")
}
func TestInlineSessionOneJobAndReader(t *testing.T) {
	term := fakeInline()
	svc := &inlineServiceFixture{}
	s, done := startInlineTest(t, term, svc, nil)
	runInlineScan(t, term)
	term.keys <- "enter"
	term.keys <- "enter"
	term.keys <- "ctrl+c"
	if e := waitInlineDone(t, done); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if svc.scans.Load() != 1 || svc.active.Load() != 0 || term.readers.Load() != 0 || term.maxReaders.Load() > 1 {
		t.Fatal("duplicate/leaked owner")
	}
	if s.Final.Result == nil || s.Final.Result.ScanID != "scan-fixture" || !strings.Contains(term.transcript(), "scan-fixture") {
		t.Fatal("identity lost")
	}
}
func TestInlineSessionCompletionNotDropped(t *testing.T) {
	term := fakeInline()
	svc := &inlineServiceFixture{onScan: func(ctx context.Context, p ProgressSink) (StatusResult, error) {
		for i := 0; i < 10000; i++ {
			p(ProgressEvent{Phase: "analyzing", ScanID: "scan-fixture"})
		}
		return terminalFixture("COMPLETED").Result, nil
	}}
	_, done := startInlineTest(t, term, svc, nil)
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	term.keys <- "enter"
	waitInlineFrame(t, term, "¿Iniciar este análisis?")
	term.keys <- "down"
	term.keys <- "enter"
	waitInlineFrame(t, term, "¿Qué quieres hacer ahora?")
	term.keys <- "esc"
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	term.keys <- "esc"
	waitInlineDone(t, done)
	if strings.Count(term.transcript(), "Estado reportado:") != 1 {
		t.Fatal(term.transcript())
	}
}
func TestInlineSessionTranscriptExactlyOnce(t *testing.T) {
	term := fakeInline()
	svc := &inlineServiceFixture{}
	_, done := startInlineTest(t, term, svc, nil)
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	term.keys <- "enter"
	waitInlineFrame(t, term, "¿Iniciar este análisis?")
	term.keys <- "esc"
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	term.keys <- "esc"
	waitInlineDone(t, done)
	text := term.transcript()
	if strings.Count(text, "TITVO") != 1 || strings.Count(text, "incluidos") != 1 {
		t.Fatal(text)
	}
}
func TestInlineSessionSetupSuspendsReader(t *testing.T) {
	term := fakeInline()
	svc := &inlineServiceFixture{}
	called := make(chan struct{})
	_, done := startInlineTest(t, term, svc, func(s *InlineSession) {
		s.Setup = func(context.Context) error {
			term.mu.Lock()
			active := term.active
			term.mu.Unlock()
			if active || term.readers.Load() != 0 {
				t.Error("password shares reader")
			}
			close(called)
			return nil
		}
	})
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	for _, r := range "config" {
		term.keys <- string(r)
	}
	term.keys <- "enter"
	select {
	case <-called:
	case <-time.After(3 * time.Second):
		t.Fatal("setup not invoked")
	}
	term.keys <- "esc"
	waitInlineDone(t, done)
	if term.maxReaders.Load() > 1 {
		t.Fatal("readers overlap")
	}
}
func TestInlineSessionResizeBurst(t *testing.T) {
	term := fakeInline()
	svc := &inlineServiceFixture{}
	ticks := make(chan time.Time)
	var clock atomic.Int64
	_, done := startInlineTest(t, term, svc, func(s *InlineSession) {
		s.ResizeTicks = ticks
		s.Now = func() time.Time { return time.Unix(0, clock.Load()) }
	})
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	term.keys <- "enter"
	waitInlineFrame(t, term, "¿Iniciar este análisis?")
	term.keys <- "down"
	term.resize(50, 14)
	ticks <- time.Now()
	waitInlineFrame(t, term, "Ajustando tamaño")
	term.keys <- "enter"
	clock.Store(int64(100 * time.Millisecond))
	term.resize(56, 16)
	ticks <- time.Now()
	waitInlineFrame(t, term, "Ajustando tamaño")
	clock.Store(int64(350 * time.Millisecond))
	ticks <- time.Now()
	waitInlineFrame(t, term, "¿Iniciar este análisis?")
	term.keys <- "ctrl+c"
	waitInlineDone(t, done)
	if svc.scans.Load() != 0 || term.abandoned != 1 || term.discarded < 1 {
		t.Fatalf("resize unsafe: scans%d abandon%d discard%d", svc.scans.Load(), term.abandoned, term.discarded)
	}
}
func TestInlineSessionEnterRechecksViewport(t *testing.T) {
	term := fakeInline()
	svc := &inlineServiceFixture{}
	_, done := startInlineTest(t, term, svc, nil)
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	term.keys <- "enter"
	waitInlineFrame(t, term, "¿Iniciar este análisis?")
	term.keys <- "down"
	term.resize(39, 9)
	term.keys <- "enter"
	waitInlineFrame(t, term, "Ajustando tamaño")
	term.keys <- "ctrl+c"
	waitInlineDone(t, done)
	if svc.scans.Load() != 0 {
		t.Fatal("unpolled resize uploaded")
	}
}
func TestInlineSessionDoesNotAnimateHistory(t *testing.T) {
	term := fakeInline()
	svc := &inlineServiceFixture{}
	ticks := make(chan time.Time)
	_, done := startInlineTest(t, term, svc, func(s *InlineSession) { s.Ticks = ticks; s.Caps.Animate = true })
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	term.keys <- "enter"
	waitInlineFrame(t, term, "¿Iniciar este análisis?")
	before := term.transcript()
	for i := 0; i < 8; i++ {
		ticks <- time.Now()
	}
	term.keys <- "ctrl+c"
	waitInlineDone(t, done)
	if before != term.transcript() {
		t.Fatal("history animated or duplicated")
	}
}
func TestInlineSessionLateEvents(t *testing.T) {
	term := fakeInline()
	svc := &inlineServiceFixture{}
	var late ProgressSink
	svc.onScan = func(ctx context.Context, p ProgressSink) (StatusResult, error) {
		late = p
		<-ctx.Done()
		return StatusResult{ScanID: "scan-fixture"}, ctx.Err()
	}
	_, done := startInlineTest(t, term, svc, nil)
	runInlineScan(t, term)
	term.keys <- "esc"
	waitInlineFrame(t, term, "¿Qué quieres hacer ahora?")
	term.keys <- "esc"
	waitInlineFrame(t, term, "¿Qué quieres revisar?")
	late(ProgressEvent{ScanID: "obsolete"})
	term.keys <- "enter"
	waitInlineFrame(t, term, "¿Iniciar este análisis?")
	term.keys <- "ctrl+c"
	waitInlineDone(t, done)
	if strings.Contains(term.transcript(), "obsolete") {
		t.Fatal("stale progress leaked")
	}
}
