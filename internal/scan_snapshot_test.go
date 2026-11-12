package internal

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func snapshotPlan(t *testing.T, scope ScanScope) (string, ScanPlan) {
	t.Helper()
	work, _ := sourceFixture(t)
	p, e := (Planner{}).Plan(context.Background(), optionsFor(work, scope))
	if e != nil {
		t.Fatal(e)
	}
	return work, p
}
func TestSnapshotArchiveMatchesPlan(t *testing.T) {
	_, p := snapshotPlan(t, ScopeStaged)
	s, e := (SnapshotBuilder{}).Build(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	f, e := os.Open(s.ArchivePath)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	h, e := tr.Next()
	if e != nil {
		t.Fatal(e)
	}
	data, e := io.ReadAll(tr)
	if e != nil {
		t.Fatal(e)
	}
	if h.Name != "main.go" || h.Size != 7 || string(data) != "indexed" {
		t.Fatalf("header=%+v content=%q", h, data)
	}
	if _, e = tr.Next(); e != io.EOF {
		t.Fatal("unexpected member")
	}
}
func TestSnapshotChangedWorkingTreeFails(t *testing.T) {
	work, p := snapshotPlan(t, ScopeFull)
	fixtureWrite(t, work, "main.go", "changed")
	_, e := (SnapshotBuilder{}).Build(context.Background(), p)
	var se *ScanError
	if !errors.As(e, &se) || se.Kind != "plan-changed" {
		t.Fatalf("err=%v", e)
	}
}
func TestSnapshotRejectsPathEscape(t *testing.T) {
	_, p := snapshotPlan(t, ScopeStaged)
	p.Files[0].Path = "../outside"
	if _, e := (SnapshotBuilder{}).Build(context.Background(), p); e == nil {
		t.Fatal("unsafe tar path")
	}
}
func TestSnapshotDoesNotFollowReplacedSymlink(t *testing.T) {
	work, p := snapshotPlan(t, ScopeFull)
	os.Remove(filepath.Join(work, "main.go"))
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("working"), 0600)
	os.Symlink(outside, filepath.Join(work, "main.go"))
	if _, e := (SnapshotBuilder{}).Build(context.Background(), p); e == nil {
		t.Fatal("symlink followed")
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }
func TestSnapshotReadWriteFailureAborts(t *testing.T) {
	p := ScanPlan{Files: []PlannedFile{{Path: "a", Size: 1, SHA256: digest([]byte("a"))}}, TotalBytes: 1}
	e := writeSnapshotArchive(context.Background(), brokenWriter{}, p, func(PlannedFile) ([]byte, error) { return []byte("a"), nil })
	if e == nil {
		t.Fatal("write failure accepted")
	}
}
func TestSnapshotCleanupOnFailureAndCancel(t *testing.T) {
	_, p := snapshotPlan(t, ScopeFull)
	temp := t.TempDir()
	p.Files[0].SHA256 = "invalid"
	_, e := (SnapshotBuilder{TempRoot: temp}).Build(context.Background(), p)
	if e == nil {
		t.Fatal("bad digest accepted")
	}
	entries, _ := os.ReadDir(temp)
	if len(entries) != 0 {
		t.Fatal("temp leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = (SnapshotBuilder{TempRoot: temp}).Build(ctx, p); e == nil {
		t.Fatal("cancel ignored")
	}
	entries, _ = os.ReadDir(temp)
	if len(entries) != 0 {
		t.Fatal("cancel leaked")
	}
}
func TestSnapshotCloseIdempotent(t *testing.T) {
	_, p := snapshotPlan(t, ScopeStaged)
	s, e := (SnapshotBuilder{}).Build(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(s.Directory); !os.IsNotExist(e) {
		t.Fatal("temp remains")
	}
}
func TestSnapshotPrivateModes(t *testing.T) {
	_, p := snapshotPlan(t, ScopeFull)
	s, e := (SnapshotBuilder{}).Build(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for path, want := range map[string]os.FileMode{s.Directory: 0700, s.ArchivePath: 0600} {
		info, e := os.Stat(path)
		if e != nil {
			t.Fatal(e)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("mode=%o want%o", info.Mode().Perm(), want)
		}
	}
}
func TestSnapshotBoundsOpenFiles(t *testing.T) {
	root := t.TempDir()
	p := ScanPlan{Repository: RepositoryIdentity{Root: root}, Scope: ScopeFull, TotalBytes: 300}
	for i := 0; i < 300; i++ {
		name := fmt.Sprintf("%d", i)
		fixtureWrite(t, root, name, "a")
		p.Files = append(p.Files, PlannedFile{Path: name, Size: 1, SHA256: digest([]byte("a"))})
	}
	before, _ := os.ReadDir("/dev/fd")
	s, e := (SnapshotBuilder{}).Build(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	after, _ := os.ReadDir("/dev/fd")
	if len(after) > len(before)+3 {
		t.Fatal("file descriptor leak")
	}
}
