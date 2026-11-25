package internal

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The original collection scenarios now exercise the public planner/snapshot
// boundary. Policy bytes always come from the working tree, never Git blobs.
func TestPlanPolicyTransport(t *testing.T) {
	for _, scope := range []ScanScope{ScopeFull, ScopeStaged, ScopeCommit} {
		for _, state := range []string{"absent", "untracked", "ignored", "unchanged", "selected"} {
			t.Run(string(scope)+"/"+state, func(t *testing.T) {
				work, _ := sourceFixture(t)
				const policy = ".titvoignore.yml"
				const content = "working tree policy"
				if state == "unchanged" || state == "selected" {
					committed := content
					if state == "selected" {
						committed = "committed policy"
					}
					fixtureWrite(t, work, policy, committed)
					runGit(t, work, "add", policy)
					runGit(t, work, "commit", "-m", "policy")
				}
				if state == "ignored" {
					fixtureWrite(t, work, ".gitignore", policy+"\n")
				}
				if state != "absent" {
					fixtureWrite(t, work, policy, content)
				}
				if state == "selected" {
					// Keep a real source focus alongside the selected policy.
					fixtureWrite(t, work, "main.go", "selected source")
					runGit(t, work, "add", policy, "main.go")
					fixtureWrite(t, work, "main.go", "working")
				}
				o := optionsFor(work, scope)
				p, err := (Planner{}).Plan(context.Background(), o)
				if err != nil {
					t.Fatal(err)
				}
				expectedSource := "working"
				if scope == ScopeStaged {
					expectedSource = "indexed"
					if state == "selected" {
						expectedSource = "selected source"
					}
				}
				if scope == ScopeCommit {
					expectedSource = "committed"
					if state == "unchanged" || state == "selected" {
						expectedSource = "indexed"
					}
				}
				assertPlanContent(t, p, "main.go", expectedSource)
				count := 0
				var total int64
				for _, f := range p.Files {
					total += f.Size
					if f.Path == policy {
						count++
						if f.BlobOID != "" || f.SHA256 != digest([]byte(content)) || f.Size != int64(len(content)) {
							t.Fatalf("policy provenance/integrity: %+v", f)
						}
					}
				}
				want := 1
				if state == "absent" {
					want = 0
				}
				if count != want || total != p.TotalBytes {
					t.Fatalf("policy count=%d want=%d total=%d plan=%d", count, want, total, p.TotalBytes)
				}
				for _, f := range p.FocusFiles {
					if f == policy {
						t.Fatal("policy is analysis focus")
					}
				}
				manifest, err := MarshalScanManifest(p)
				if err != nil {
					t.Fatal(err)
				}
				var m struct {
					Files []struct {
						Path, SHA256 string
						Size         int64
					}
					FocusFiles []string `json:"focus_files"`
				}
				if err = json.Unmarshal(manifest, &m); err != nil {
					t.Fatal(err)
				}
				count = 0
				for _, f := range m.Files {
					if f.Path == policy {
						count++
						if f.SHA256 != digest([]byte(content)) || f.Size != int64(len(content)) {
							t.Fatal("manifest integrity")
						}
					}
				}
				if count != want {
					t.Fatalf("manifest policy count=%d", count)
				}
				for _, f := range m.FocusFiles {
					if f == policy {
						t.Fatal("manifest policy focus")
					}
				}
				s, err := (SnapshotBuilder{}).Build(context.Background(), p)
				if err != nil {
					t.Fatal(err)
				}
				defer s.Close()
				f, err := os.Open(s.ArchivePath)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				gz, err := gzip.NewReader(f)
				if err != nil {
					t.Fatal(err)
				}
				defer gz.Close()
				tr := tar.NewReader(gz)
				count = 0
				for {
					h, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					b, err := io.ReadAll(tr)
					if err != nil {
						t.Fatal(err)
					}
					if h.Name == policy {
						count++
						if string(b) != content {
							t.Fatalf("archive policy=%q", b)
						}
					}
				}
				if count != want {
					t.Fatalf("archive policy count=%d", count)
				}
			})
		}
	}
}

func TestPlanPolicyOnlyFocusNeverExpandsToFull(t *testing.T) {
	for _, scope := range []ScanScope{ScopeStaged, ScopeCommit} {
		t.Run(string(scope), func(t *testing.T) {
			_, work := newRepoWithRemote(t)
			fixtureWrite(t, work, rootPolicyName, "version: 1\nexceptions: []\n")
			runGit(t, work, "add", rootPolicyName)
			if scope == ScopeCommit {
				runGit(t, work, "commit", "-m", "policy only")
			}
			s, requests, starts := testService(t, false)
			result, err := s.Scan(context.Background(), optionsFor(work, scope), "", nil)
			const want = "el foco contiene solo .titvoignore.yml; selecciona archivos fuente o usa --full"
			if err == nil || err.Error() != want || result.ScanID != "" || *requests != 0 || *starts != 0 {
				t.Fatalf("result=%+v error=%v requests=%d starts=%d", result, err, *requests, *starts)
			}
		})
	}
}

func TestPlanPolicyUnsafeReadFails(t *testing.T) {
	for _, state := range []string{"symlink", "directory", "binary", "invalid utf8", "oversized"} {
		t.Run(state, func(t *testing.T) {
			work, _ := sourceFixture(t)
			path := filepath.Join(work, ".titvoignore.yml")
			o := optionsFor(work, ScopeStaged)
			switch state {
			case "symlink":
				if err := os.Symlink("main.go", path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "binary":
				fixtureWrite(t, work, ".titvoignore.yml", "a\x00b")
			case "invalid utf8":
				fixtureWrite(t, work, ".titvoignore.yml", "\xff")
			case "oversized":
				fixtureWrite(t, work, ".titvoignore.yml", "longer than source")
				o.Limits.MaxFileBytes = 10
			}
			if _, err := (Planner{}).Plan(context.Background(), o); err == nil {
				t.Fatal("unsafe root policy accepted")
			}
		})
	}
}

func TestPlanPolicyBudgetAndSnapshotIntegrity(t *testing.T) {
	work, _ := sourceFixture(t)
	fixtureWrite(t, work, ".titvoignore.yml", "policy payload")
	o := optionsFor(work, ScopeStaged)
	p, err := (Planner{}).Plan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	assertPlanContent(t, p, ".titvoignore.yml", "policy payload")
	for _, dimension := range []string{"files", "total", "file"} {
		t.Run(dimension, func(t *testing.T) {
			limited := o
			switch dimension {
			case "files":
				limited.Limits.MaxFiles = len(p.Files) - 1
			case "total":
				limited.Limits.MaxTotalBytes = p.TotalBytes - 1
			case "file":
				limited.Limits.MaxFileBytes = 10
			}
			if _, err := (Planner{}).Plan(context.Background(), limited); err == nil {
				t.Fatal("policy budget ignored")
			}
		})
	}
	fixtureWrite(t, work, ".titvoignore.yml", "mutate payload")
	changed, err := (Planner{}).Plan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Fingerprint == p.Fingerprint {
		t.Fatal("policy change did not invalidate preview")
	}
	temp := t.TempDir()
	if _, err := (SnapshotBuilder{TempRoot: temp}).Build(context.Background(), p); err == nil {
		t.Fatal("changed policy accepted")
	}
	entries, err := os.ReadDir(temp)
	if err != nil || len(entries) != 0 {
		t.Fatalf("snapshot leaked: %v %v", entries, err)
	}
}
