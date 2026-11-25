package internal

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectScanFilesPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		present, duplicate, symlink bool
		want                        int
		wantErr                     bool
	}{
		{name: "absent preserves sources", want: 1},
		{name: "unchanged policy", present: true, want: 2},
		{name: "selected policy deduplicated", present: true, duplicate: true, want: 2},
		{name: "symlink rejected", symlink: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "main.go")
			if err := os.WriteFile(source, []byte("working tree source"), 0600); err != nil {
				t.Fatal(err)
			}
			policy := filepath.Join(root, ".titvoignore.yml")
			if tc.present {
				if err := os.WriteFile(policy, []byte("working tree policy"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.symlink {
				if err := os.Symlink(source, policy); err != nil {
					t.Fatal(err)
				}
			}
			selected := []string{source}
			if tc.duplicate {
				selected = append(selected, policy, policy)
			}
			files, err := collectScanFiles(selected, root)
			for _, f := range files {
				defer f.File.Close()
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v", err)
			}
			if tc.wantErr {
				return
			}
			if len(files) != tc.want {
				t.Fatalf("files=%d want=%d", len(files), tc.want)
			}
			for _, f := range files {
				content, e := io.ReadAll(f.File)
				if e != nil {
					t.Fatal(e)
				}
				want := "working tree source"
				if f.Path == ".titvoignore.yml" {
					want = "working tree policy"
				}
				if string(content) != want || f.Size != int64(len(content)) {
					t.Fatalf("incorrect content/size: %+v %q", f, content)
				}
			}
		})
	}
}
