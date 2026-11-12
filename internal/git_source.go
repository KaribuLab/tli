package internal

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type GitRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}
type ExecGitRunner struct{}

func (ExecGitRunner) Run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	// Git diagnostics may contain credential-bearing URLs; never return raw stderr.
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Git %s falló", args[0])
	}
	return out, nil
}

type GitSource struct{ Runner GitRunner }

func (g GitSource) run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	if g.Runner == nil {
		g.Runner = ExecGitRunner{}
	}
	return g.Runner.Run(ctx, dir, args...)
}
func (g GitSource) Identity(ctx context.Context, o ScanOptions) (RepositoryIdentity, error) {
	var id RepositoryIdentity
	path := o.Path
	if path == "" {
		path = "."
	}
	root, err := g.run(ctx, path, "rev-parse", "--show-toplevel")
	if err != nil {
		return id, err
	}
	id.Root = strings.TrimSpace(string(root))
	ref := "HEAD"
	if o.Commit != "" {
		ref = o.Commit
	}
	sha, err := g.run(ctx, id.Root, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return id, err
	}
	id.Commit = strings.TrimSpace(string(sha))
	branch, err := g.run(ctx, id.Root, "branch", "--show-current")
	if err != nil {
		return id, err
	}
	id.Branch = strings.TrimSpace(string(branch))
	if id.Branch == "" {
		for _, key := range []string{"BITBUCKET_BRANCH", "GITHUB_HEAD_REF", "GITHUB_REF_NAME"} {
			if id.Branch = os.Getenv(key); id.Branch != "" {
				break
			}
		}
	}
	if id.Branch == "" {
		return id, fmt.Errorf("HEAD detached: indica una rama CI válida; no se publicará ni modificará Git")
	}
	if _, err = g.run(ctx, id.Root, "check-ref-format", "--branch", id.Branch); err != nil {
		return id, fmt.Errorf("nombre de rama no válido")
	}
	remote := o.Remote
	if remote == "" {
		remote = "origin"
	}
	if strings.HasPrefix(remote, "-") {
		return id, fmt.Errorf("remote no válido")
	}
	raw, err := g.run(ctx, id.Root, "remote", "get-url", "--", remote)
	if err != nil {
		return id, fmt.Errorf("no se pudo leer el remote local")
	}
	id.URL = sanitizeRepositoryURL(string(raw))
	if id.URL == "" {
		return id, fmt.Errorf("URL de repositorio no válida")
	}
	return id, nil
}
