package internal

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInteractiveKeyDecoder(t *testing.T) {
	for _, tc := range []struct{ raw, key string }{{"\x1b[A", "up"}, {"\x1b[B", "down"}, {"\x1b[C", "right"}, {"\x1b[D", "left"}, {"\x1b[5~", "pageup"}, {"\x1b[6~", "pagedown"}, {"\t", "tab"}, {"\r", "enter"}, {"\n", "enter"}, {"\x7f", "backspace"}, {"q", "q"}, {"ñ", "ñ"}, {"\x1b", "esc"}, {"\x03", "ctrl+c"}, {"\x04", "eof"}} {
		got, e := ReadInteractiveKey(context.Background(), strings.NewReader(tc.raw))
		if e != nil || got != tc.key {
			t.Fatalf("%q =>%q %v", tc.raw, got, e)
		}
	}
}
func TestInteractiveKeyCancelEOF(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := ReadInteractiveKey(ctx, strings.NewReader("a")); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := ReadInteractiveKey(context.Background(), strings.NewReader("")); e != io.EOF {
		t.Fatal(e)
	}
}
func TestInteractiveKeyFragmentedEscapeAndTimeout(t *testing.T) {
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	w.Write([]byte{27})
	started := time.Now()
	got, e := ReadInteractiveKey(context.Background(), r)
	if e != nil || got != "esc" || time.Since(started) > 200*time.Millisecond {
		t.Fatal("ESC timeout", got, e)
	}
	w.Write([]byte("\x1b["))
	go func() { w.Write([]byte("B")) }()
	got, e = ReadInteractiveKey(context.Background(), r)
	if e != nil || got != "down" {
		t.Fatal("fragmented escape", got, e)
	}
}
