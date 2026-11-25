package internal

import (
	"context"
	"os"
	"testing"
)

func TestNativeInlineDiscardReturnsUrgentControl(t *testing.T) {
	for _, tc := range []struct{ bytes, key string }{{"abc\x03", "ctrl+c"}, {"abc\x04", "eof"}, {"abc\x1b", "esc"}} {
		t.Run(tc.key, func(t *testing.T) {
			r, w, e := os.Pipe()
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			defer w.Close()
			w.Write([]byte(tc.bytes))
			term := &NativeInlineTerminal{In: r, region: ownedInlineRegion{active: true}}
			got, e := term.DiscardInput(context.Background())
			if e != nil || got != tc.key {
				t.Fatalf("discard lost %s: %q %v", tc.key, got, e)
			}
		})
	}
}
