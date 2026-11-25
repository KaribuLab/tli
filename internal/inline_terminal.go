package internal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/term"
)

var ErrInlineGeometry = errors.New("la geometría de la región inline cambió")
var inlineSGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)

type InlineTerminal interface {
	Begin() error
	End() error
	Size() (int, int, error)
	ResizeEpoch() uint64
	ReadKey(context.Context) (string, error)
	DiscardInput(context.Context) (string, error)
	DrawActive(InlineFrame) error
	CommitBlock(string) error
	AbandonActive(string) error
}
type ownedInlineRegion struct {
	out                 io.Writer
	width, height, rows int
	active              bool
	restore             func() error
}

func (r *ownedInlineRegion) begin(restore func() error) error {
	if r.active {
		return nil
	}
	r.active = true
	r.rows = 0
	r.restore = restore
	return nil
}
func inlineTextValid(text string, multiline bool) bool {
	plain := inlineSGR.ReplaceAllString(text, "")
	for _, c := range plain {
		if c == '\n' && multiline {
			continue
		}
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func (r *ownedInlineRegion) clearOwned() string {
	if r.rows == 0 {
		return ""
	}
	var out strings.Builder
	out.WriteString("\r\x1b[2K")
	for i := 1; i < r.rows; i++ {
		out.WriteString("\x1b[1A\r\x1b[2K")
	}
	return out.String()
}
func (r *ownedInlineRegion) write(s string) error {
	n, e := io.WriteString(r.out, s)
	if e == nil && n != len(s) {
		e = io.ErrShortWrite
	}
	if e != nil {
		r.rows = 0
		return errors.Join(e, r.end())
	}
	return nil
}
func (r *ownedInlineRegion) draw(frame InlineFrame) error {
	if !r.active {
		return errors.New("terminal inline no iniciado")
	}
	if len(frame.Lines) > max(0, r.height-2) {
		return ErrInlineGeometry
	}
	for _, line := range frame.Lines {
		if !inlineTextValid(line, false) {
			return errors.New("control no permitido en frame")
		}
		if CellWidth(inlineSGR.ReplaceAllString(line, "")) > max(0, r.width-1) {
			return ErrInlineGeometry
		}
	}
	output := r.clearOwned() + strings.Join(frame.Lines, "\r\n")
	if frame.CursorVisible {
		output += "\x1b[?25h"
	} else {
		output += "\x1b[?25l"
	}
	if e := r.write(output); e != nil {
		return e
	}
	r.rows = len(frame.Lines)
	return nil
}
func (r *ownedInlineRegion) commit(text string) error {
	if !r.active {
		return errors.New("terminal inline no iniciado")
	}
	if !inlineTextValid(text, true) {
		return errors.New("control no permitido en transcript")
	}
	output := r.clearOwned() + strings.ReplaceAll(strings.TrimRight(text, "\n"), "\n", "\r\n") + "\r\n"
	if e := r.write(output); e != nil {
		return e
	}
	r.rows = 0
	return nil
}
func (r *ownedInlineRegion) abandon(reason string) error {
	if !r.active || r.rows == 0 {
		return nil
	}
	r.rows = 0
	return r.write("\r\n" + strings.ReplaceAll(SafeTerminalText(reason), "\n", " ") + "\r\n")
}
func (r *ownedInlineRegion) end() error {
	if !r.active {
		return nil
	}
	r.active = false
	output := r.clearOwned() + "\x1b[0m\x1b[?25h\r\n"
	r.rows = 0
	_, writeErr := io.WriteString(r.out, output)
	var restoreErr error
	if r.restore != nil {
		restoreErr = r.restore()
		r.restore = nil
	}
	return errors.Join(writeErr, restoreErr)
}

type NativeInlineTerminal struct {
	In, Out                *os.File
	Caps                   TerminalOptions
	region                 ownedInlineRegion
	epoch                  atomic.Uint64
	seenEpoch              uint64
	pollResize, stopResize func()
}

func NewInlineTerminal(in, out *os.File, caps TerminalOptions) *NativeInlineTerminal {
	return &NativeInlineTerminal{In: in, Out: out, Caps: caps, region: ownedInlineRegion{out: out}}
}
func (t *NativeInlineTerminal) Size() (int, int, error) {
	if t.Out == nil {
		return 0, 0, errors.New("terminal no disponible")
	}
	return term.GetSize(int(t.Out.Fd()))
}
func inlinePlatformSupported() bool { return runtime.GOOS != "windows" && runtime.GOOS != "plan9" }
func (t *NativeInlineTerminal) Begin() error {
	if t.region.active {
		return nil
	}
	if !inlinePlatformSupported() || !t.Caps.Interactive || t.In == nil || t.Out == nil || !term.IsTerminal(int(t.In.Fd())) || !term.IsTerminal(int(t.Out.Fd())) {
		return errors.New("IO inline no compatible")
	}
	w, h, e := t.Size()
	if e != nil {
		return e
	}
	state, e := term.MakeRaw(int(t.In.Fd()))
	if e != nil {
		return e
	}
	t.pollResize, t.stopResize = watchInlineResize(func() { t.epoch.Add(1) })
	t.seenEpoch = t.ResizeEpoch()
	t.region.width = w
	t.region.height = h
	return t.region.begin(func() error { return term.Restore(int(t.In.Fd()), state) })
}
func (t *NativeInlineTerminal) ResizeEpoch() uint64 {
	if t.pollResize != nil {
		t.pollResize()
	}
	return t.epoch.Load()
}
func (t *NativeInlineTerminal) refresh() (bool, error) {
	epoch := t.ResizeEpoch()
	w, h, e := t.Size()
	if e != nil {
		return false, e
	}
	changed := epoch != t.seenEpoch || w != t.region.width || h != t.region.height
	if changed {
		if e = t.region.abandon("Vista anterior anulada: cambió el tamaño; revisa otra vez."); e != nil {
			return true, e
		}
		t.region.width = w
		t.region.height = h
		t.seenEpoch = epoch
	}
	return changed, nil
}
func (t *NativeInlineTerminal) DrawActive(f InlineFrame) error {
	changed, e := t.refresh()
	if e != nil {
		return e
	}
	if changed {
		return ErrInlineGeometry
	}
	return t.region.draw(f)
}
func (t *NativeInlineTerminal) CommitBlock(text string) error {
	if _, e := t.refresh(); e != nil {
		return e
	}
	return t.region.commit(text)
}
func (t *NativeInlineTerminal) AbandonActive(reason string) error { return t.region.abandon(reason) }
func (t *NativeInlineTerminal) End() error {
	defer func() {
		if t.stopResize != nil {
			t.stopResize()
			t.stopResize = nil
			t.pollResize = nil
		}
	}()
	if !t.region.active {
		return nil
	}
	if _, e := t.refresh(); e != nil {
		t.region.rows = 0
		return errors.Join(e, t.region.end())
	}
	return t.region.end()
}
func (t *NativeInlineTerminal) DiscardInput(ctx context.Context) (string, error) {
	if !t.region.active {
		return "", nil
	}
	drain, cancel := context.WithTimeout(ctx, 5*time.Millisecond)
	defer cancel()
	for {
		key, e := ReadInteractiveKey(drain, t.In)
		if inlineControl(key) != "" {
			return key, nil
		}
		if e != nil {
			if e == io.EOF {
				return "eof", nil
			}
			if errors.Is(e, context.DeadlineExceeded) {
				return "", nil
			}
			return "", e
		}
	}
}
func (t *NativeInlineTerminal) ReadKey(ctx context.Context) (string, error) {
	if t.In == nil {
		return "", fmt.Errorf("entrada no disponible")
	}
	return ReadInteractiveKey(ctx, t.In)
}
