package internal

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
func newRepoWithRemote(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "work")
	runGit(t, root, "init", "--bare", "-b", "main", remote)
	runGit(t, root, "clone", "-q", remote, work)
	runGit(t, work, "checkout", "-q", "-b", "main")
	commitFile(t, work, "a.txt")
	runGit(t, work, "push", "-q", "-u", "origin", "main")
	return remote, work
}
func commitFile(t *testing.T, work, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(work, name), []byte(name), 0600); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", ".")
	runGit(t, work, "commit", "-q", "-m", "fixture")
}

// Regression expectations for publishing were intentionally replaced by
// TestIdentityNeverPublishes: scanning must never mutate a remote.
