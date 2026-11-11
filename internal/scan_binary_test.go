package internal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name string, content []byte) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestIsBinaryFile(t *testing.T) {
	png := append([]byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 0x0d}, []byte("IHDR")...)
	big := bytes.Repeat([]byte("código seguro ñandú 日本語\n"), 1000) // > 8000 bytes, multi-byte runes

	cases := []struct {
		name    string
		content []byte
		want    bool
	}{
		{"png", png, true},
		{"go source", []byte("package main\n\nfunc main() {}\n"), false},
		{"utf8 accents", []byte("configuración: año\n"), false},
		{"empty", []byte{}, false},
		{"nul in text", []byte("abc\x00def"), true},
		{"latin1 (invalid utf8)", []byte("a\xf1o"), true},
		{"large utf8 cut mid-rune at sniff boundary", big, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := writeTemp(t, "f", tc.content)
			got, err := isBinaryFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("isBinaryFile = %v, want %v", got, tc.want)
			}
			// Offset must be restored so the file can still be uploaded.
			if pos, _ := f.Seek(0, 1); pos != 0 {
				t.Fatalf("offset after sniff = %d, want 0", pos)
			}
		})
	}
}

func TestOpenFileSecurelySkipsBinary(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "logo.png"), []byte{0x89, 'P', 'N', 'G', 0, 0}, 0644)
	os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0644)
	t.Chdir(root)

	if info, err := openFileSecurely("logo.png", root); err != nil || info != nil {
		t.Fatalf("binary file should be skipped: info=%v err=%v", info, err)
	}
	info, err := openFileSecurely("main.go", root)
	if err != nil || info == nil {
		t.Fatalf("text file should be opened: info=%v err=%v", info, err)
	}
	info.file.Close()
}
