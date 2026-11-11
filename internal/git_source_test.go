package internal

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type readOnlyGit struct{ t *testing.T }

func (r readOnlyGit) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	for _, cmd := range []string{"push", "fetch", "ls-remote", "checkout"} {
		if args[0] == cmd {
			r.t.Fatalf("unexpected mutating/network Git call: %v", args)
		}
	}
	return (ExecGitRunner{}).Run(ctx, dir, args...)
}
func TestIdentityNeverPublishes(t *testing.T) {
	for _, mode := range []string{"missing-branch", "ahead", "unreachable"} {
		t.Run(mode, func(t *testing.T) {
			remote, work := newRepoWithRemote(t)
			before := runGit(t, remote, "rev-parse", "main")
			if mode == "missing-branch" {
				runGit(t, work, "checkout", "-b", "feature")
			}
			commitFile(t, work, "b.txt")
			if mode == "unreachable" {
				runGit(t, work, "remote", "set-url", "origin", filepath.Join(t.TempDir(), "missing"))
			}
			id, err := (GitSource{Runner: readOnlyGit{t}}).Identity(context.Background(), ScanOptions{Path: work, Remote: "origin"})
			if err != nil || id.Commit != runGit(t, work, "rev-parse", "HEAD") {
				t.Fatalf("identity=%+v err=%v", id, err)
			}
			if after := runGit(t, remote, "rev-parse", "main"); after != before {
				t.Fatal("remote changed")
			}
		})
	}
}
func TestIdentityUsesPathWithoutChdir(t *testing.T) {
	_, work := newRepoWithRemote(t)
	cwd, _ := os.Getwd()
	id, err := (GitSource{}).Identity(context.Background(), ScanOptions{Path: work})
	after, _ := os.Getwd()
	physical, pathErr := filepath.EvalSymlinks(work)
	if pathErr != nil {
		t.Fatal(pathErr)
	}
	if err != nil || id.Root != physical || cwd != after {
		t.Fatalf("%+v err=%v cwd changed=%v", id, err, cwd != after)
	}
}
func TestRepositoryURLRedaction(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://user:secret@example.test/repo.git?token=secret#private", "https://example.test/repo.git"},
		{"https://example.test/repo.git?token=secret", "https://example.test/repo.git"},
		{"git@example.test:org/repo.git\n", "git@example.test:org/repo.git"},
	} {
		if got := sanitizeRepositoryURL(tc.in); got != tc.want {
			t.Fatalf("got %q want %q", got, tc.want)
		}
	}
}
func TestDetachedIdentity(t *testing.T) {
	_, work := newRepoWithRemote(t)
	runGit(t, work, "checkout", "--detach")
	for _, k := range []string{"BITBUCKET_BRANCH", "GITHUB_HEAD_REF", "GITHUB_REF_NAME"} {
		t.Setenv(k, "")
	}
	_, err := (GitSource{}).Identity(context.Background(), ScanOptions{Path: work})
	if err == nil {
		t.Fatal("detached without branch must fail locally")
	}
	t.Setenv("BITBUCKET_BRANCH", "ci/test")
	id, err := (GitSource{}).Identity(context.Background(), ScanOptions{Path: work})
	if err != nil || id.Branch != "ci/test" {
		t.Fatalf("%+v %v", id, err)
	}
	t.Setenv("BITBUCKET_BRANCH", "--bad")
	if _, err = (GitSource{}).Identity(context.Background(), ScanOptions{Path: work}); err == nil {
		t.Fatal("invalid branch")
	}
}
func TestMissingRemoteFailsLocally(t *testing.T) {
	_, work := newRepoWithRemote(t)
	runGit(t, work, "remote", "remove", "origin")
	if _, err := (GitSource{}).Identity(context.Background(), ScanOptions{Path: work}); err == nil || strings.Contains(err.Error(), "https://") {
		t.Fatalf("expected safe local error: %v", err)
	}
}
