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
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// newRepoWithRemote creates a bare remote and a clone with one commit on
// branch main already pushed. Returns remote and work dirs.
func newRepoWithRemote(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	remote := filepath.Join(root, "remote.git")
	work := filepath.Join(root, "work")
	runGit(t, root, "init", "--bare", "-b", "main", remote)
	runGit(t, root, "clone", "-q", remote, work)
	runGit(t, work, "checkout", "-q", "-b", "main")
	os.WriteFile(filepath.Join(work, "a.txt"), []byte("a"), 0644)
	runGit(t, work, "add", ".")
	runGit(t, work, "commit", "-q", "-m", "first")
	runGit(t, work, "push", "-q", "-u", "origin", "main")
	return remote, work
}

func commitFile(t *testing.T, work, name string) {
	t.Helper()
	os.WriteFile(filepath.Join(work, name), []byte(name), 0644)
	runGit(t, work, "add", ".")
	runGit(t, work, "commit", "-q", "-m", name)
}

func TestCurrentRemoteBranch(t *testing.T) {
	t.Run("branch already published: no push, same sha", func(t *testing.T) {
		remote, work := newRepoWithRemote(t)
		before := runGit(t, remote, "rev-parse", "main")
		t.Chdir(work)

		branch, err := currentRemoteBranch("origin")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if branch != "main" {
			t.Fatalf("branch = %q, want main", branch)
		}
		if after := runGit(t, remote, "rev-parse", "main"); after != before {
			t.Fatalf("remote changed: %s -> %s", before, after)
		}
	})

	t.Run("branch missing on remote: pushes it", func(t *testing.T) {
		remote, work := newRepoWithRemote(t)
		runGit(t, work, "checkout", "-q", "-b", "feature")
		commitFile(t, work, "b.txt")
		local := runGit(t, work, "rev-parse", "HEAD")
		t.Chdir(work)

		branch, err := currentRemoteBranch("origin")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if branch != "feature" {
			t.Fatalf("branch = %q, want feature", branch)
		}
		if got := runGit(t, remote, "rev-parse", "feature"); got != local {
			t.Fatalf("remote feature = %s, want %s", got, local)
		}
	})

	t.Run("local ahead of remote: pushes", func(t *testing.T) {
		remote, work := newRepoWithRemote(t)
		commitFile(t, work, "c.txt")
		local := runGit(t, work, "rev-parse", "HEAD")
		t.Chdir(work)

		if _, err := currentRemoteBranch("origin"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := runGit(t, remote, "rev-parse", "main"); got != local {
			t.Fatalf("remote main = %s, want %s", got, local)
		}
	})

	t.Run("detached HEAD: clear error", func(t *testing.T) {
		_, work := newRepoWithRemote(t)
		runGit(t, work, "checkout", "-q", "--detach")
		t.Chdir(work)

		if _, err := currentRemoteBranch("origin"); err == nil {
			t.Fatal("expected error on detached HEAD")
		}
	})
}
