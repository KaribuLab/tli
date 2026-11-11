package internal

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureWrite(t *testing.T, root, path, content string) {
	t.Helper()
	p := filepath.Join(root, path)
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte(content), 0600); e != nil {
		t.Fatal(e)
	}
}
func optionsFor(root string, scope ScanScope) ScanOptions {
	return ScanOptions{Path: root, Scope: scope, Limits: DefaultLimits()}
}
func assertPlanContent(t *testing.T, p ScanPlan, path, content string) {
	t.Helper()
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(content)))
	for _, f := range p.Files {
		if f.Path == path {
			if f.SHA256 != want {
				t.Fatalf("%s wrong bytes: %+v", path, f)
			}
			return
		}
	}
	t.Fatalf("file missing: %s %+v", path, p)
}
func sourceFixture(t *testing.T) (string, string) {
	t.Helper()
	_, work := newRepoWithRemote(t)
	fixtureWrite(t, work, "main.go", "committed")
	runGit(t, work, "add", ".")
	runGit(t, work, "commit", "-m", "code")
	sha := runGit(t, work, "rev-parse", "HEAD")
	fixtureWrite(t, work, "main.go", "indexed")
	runGit(t, work, "add", "main.go")
	fixtureWrite(t, work, "main.go", "working")
	return work, sha
}
func TestPlanCommitUsesCommittedBytes(t *testing.T) {
	work, sha := sourceFixture(t)
	o := optionsFor(work, ScopeCommit)
	o.Commit = sha
	p, e := (Planner{}).Plan(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, "main.go", "committed")
}
func TestPlanStagedUsesIndexBytes(t *testing.T) {
	work, _ := sourceFixture(t)
	p, e := (Planner{}).Plan(context.Background(), optionsFor(work, ScopeStaged))
	if e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, "main.go", "indexed")
}
func TestPlanFullUsesTrackedWorkingTree(t *testing.T) {
	work, _ := sourceFixture(t)
	fixtureWrite(t, work, "untracked", "excluded")
	p, e := (Planner{}).Plan(context.Background(), optionsFor(work, ScopeFull))
	if e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, "main.go", "working")
	for _, f := range p.Files {
		if f.Path == "untracked" {
			t.Fatal("untracked included")
		}
	}
}
func TestPlanRootMergeAndRename(t *testing.T) {
	_, work := newRepoWithRemote(t)
	root := runGit(t, work, "rev-parse", "HEAD")
	o := optionsFor(work, ScopeCommit)
	o.Commit = root
	p, e := (Planner{}).Plan(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, "a.txt", "a.txt")
	runGit(t, work, "checkout", "-b", "feature")
	commitFile(t, work, "feature.go")
	runGit(t, work, "checkout", "main")
	commitFile(t, work, "main.go")
	runGit(t, work, "merge", "--no-ff", "feature", "-m", "merge")
	o.Commit = "HEAD"
	p, e = (Planner{}).Plan(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, "feature.go", "feature.go")
	if len(p.Files) != 1 {
		t.Fatalf("merge scope=%+v", p.Files)
	}
	runGit(t, work, "mv", "a.txt", "renamed.txt")
	runGit(t, work, "commit", "-m", "rename")
	p, e = (Planner{}).Plan(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, "renamed.txt", "a.txt")
	if len(p.Excluded) != 1 || p.Excluded[0].Reason != "deleted" {
		t.Fatalf("deleted not recorded: %+v", p.Excluded)
	}
}
func TestPlanNULSafePaths(t *testing.T) {
	_, work := newRepoWithRemote(t)
	name := "espacio ñ\nsalto.go"
	fixtureWrite(t, work, name, "hello")
	runGit(t, work, "add", ".")
	p, e := (Planner{}).Plan(context.Background(), optionsFor(work, ScopeStaged))
	if e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, name, "hello")
}
func TestPlanRejectsUnmergedIndex(t *testing.T) {
	_, work := newRepoWithRemote(t)
	runGit(t, work, "checkout", "-b", "feature")
	fixtureWrite(t, work, "a.txt", "feature")
	runGit(t, work, "commit", "-am", "feature")
	runGit(t, work, "checkout", "main")
	fixtureWrite(t, work, "a.txt", "main")
	runGit(t, work, "commit", "-am", "main")
	_, err := (ExecGitRunner{}).Run(context.Background(), work, "merge", "feature")
	if err == nil {
		t.Fatal("fixture needs conflict")
	}
	if _, e := (Planner{}).Plan(context.Background(), optionsFor(work, ScopeStaged)); e == nil {
		t.Fatal("unmerged index accepted")
	}
}
func TestPlanExcludesLinksAndSensitive(t *testing.T) {
	for _, scope := range []ScanScope{ScopeFull, ScopeStaged, ScopeCommit} {
		t.Run(string(scope), func(t *testing.T) {
			_, work := newRepoWithRemote(t)
			for _, name := range []string{".env", ".env.example", "private.pem", "id_rsa", "node_modules/lib.js", "dist/app.js"} {
				fixtureWrite(t, work, name, "secret")
			}
			if e := os.Symlink("a.txt", filepath.Join(work, "link")); e != nil {
				t.Fatal(e)
			}
			runGit(t, work, "add", ".")
			if scope == ScopeCommit {
				runGit(t, work, "commit", "-m", "policy")
			}
			p, e := (Planner{}).Plan(context.Background(), optionsFor(work, scope))
			if e != nil {
				t.Fatal(e)
			}
			if len(p.Excluded) != 7 {
				t.Fatalf("excluded=%+v", p.Excluded)
			}
		})
	}
}
func TestPlanBudgets(t *testing.T) {
	got := DefaultLimits()
	if got.MaxFileBytes != 1<<20 || got.MaxTotalBytes != 50<<20 || got.MaxFiles != 10000 {
		t.Fatal(got)
	}
	work, _ := sourceFixture(t)
	for _, l := range []Limits{{MaxFileBytes: 3, MaxTotalBytes: 100, MaxFiles: 10}, {MaxFileBytes: 100, MaxTotalBytes: 5, MaxFiles: 10}, {MaxFileBytes: 100, MaxTotalBytes: 100, MaxFiles: 1}, {}} {
		o := optionsFor(work, ScopeFull)
		o.Limits = l
		if _, e := (Planner{}).Plan(context.Background(), o); e == nil {
			t.Fatalf("budget ignored: %+v", l)
		}
	}
}
func TestPlanUTF8AndBinaryPolicy(t *testing.T) {
	_, work := newRepoWithRemote(t)
	fixtureWrite(t, work, "invalid", strings.Repeat("a", 8100)+"\xff")
	fixtureWrite(t, work, "nul", "a\x00b")
	fixtureWrite(t, work, "valid", strings.Repeat("a", 7999)+"ñ")
	runGit(t, work, "add", ".")
	p, e := (Planner{}).Plan(context.Background(), optionsFor(work, ScopeStaged))
	if e != nil {
		t.Fatal(e)
	}
	if len(p.Excluded) != 2 {
		t.Fatalf("excluded=%+v", p.Excluded)
	}
	assertPlanContent(t, p, "valid", strings.Repeat("a", 7999)+"ñ")
}

type changingIndexRunner struct {
	t       *testing.T
	changed bool
}

func (r *changingIndexRunner) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	out, e := (ExecGitRunner{}).Run(ctx, dir, args...)
	if !r.changed && ((args[0] == "ls-files") || (args[0] == "diff" && strings.Contains(strings.Join(args, " "), "--raw"))) {
		r.changed = true
		fixtureWrite(r.t, dir, "a.txt", "a.txt")
		runGit(r.t, dir, "add", "a.txt")
		fixtureWrite(r.t, dir, "c.go", "prepared-c")
		runGit(r.t, dir, "add", "c.go")
	}
	return out, e
}
func TestStagedPlanNeverMixesIndexVersions(t *testing.T) {
	_, root := newRepoWithRemote(t)
	fixtureWrite(t, root, "c.go", "HEAD-c")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "c")
	fixtureWrite(t, root, "a.txt", "prepared-a")
	runGit(t, root, "add", "a.txt")
	runner := &changingIndexRunner{t: t}
	p, e := (Planner{Git: GitSource{Runner: runner}}).Plan(context.Background(), optionsFor(root, ScopeStaged))
	if e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, "a.txt", "prepared-a")
	if len(p.Files) != 1 {
		t.Fatal(p.Files)
	}
}
func TestPlanReadErrorIsNotExclusion(t *testing.T) {
	_, work := newRepoWithRemote(t)
	os.Remove(filepath.Join(work, "a.txt"))
	os.Mkdir(filepath.Join(work, "a.txt"), 0700)
	if _, e := (Planner{}).Plan(context.Background(), optionsFor(work, ScopeFull)); e == nil {
		t.Fatal("unreadable selected file accepted")
	}
}
