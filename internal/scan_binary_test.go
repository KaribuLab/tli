package internal

import (
	"bytes"
	"context"
	"testing"
)

// Regression fixtures from v0.12.2 now exercise full-content policy rather than
// an 8000-byte sniff. The source read used for hashing is also used for UTF-8.
func TestIsBinaryFile(t *testing.T) {
	png := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 0x0d}, []byte("IHDR")...)
	big := bytes.Repeat([]byte("código seguro ñandú 日本語\n"), 1000)
	for _, tc := range []struct {
		name    string
		content []byte
		want    bool
	}{
		{"png", png, true}, {"go source", []byte("package main\n\nfunc main() {}\n"), false},
		{"utf8 accents", []byte("configuración: año\n"), false}, {"empty", []byte{}, false},
		{"nul in text", []byte("abc\x00def"), true}, {"latin1 (invalid utf8)", []byte("a\xf1o"), true}, {"large utf8 cut mid-rune at sniff boundary", big, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := binaryContent(tc.content); got != tc.want {
				t.Fatalf("binary=%v want%v", got, tc.want)
			}
		})
	}
}
func TestOpenFileSecurelySkipsBinary(t *testing.T) {
	_, root := newRepoWithRemote(t)
	fixtureWrite(t, root, "logo.png", string([]byte{0x89, 'P', 'N', 'G', 0, 0}))
	fixtureWrite(t, root, "main.go", "package main\n")
	runGit(t, root, "add", ".")
	p, e := (Planner{}).Plan(context.Background(), optionsFor(root, ScopeStaged))
	if e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, "main.go", "package main\n")
	if len(p.Excluded) != 1 || p.Excluded[0].Path != "logo.png" || p.Excluded[0].Reason != "binary" {
		t.Fatal(p.Excluded)
	}
}
