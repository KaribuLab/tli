package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/KaribuLab/tli/internal"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type ScanScope = internal.ScanScope

const (
	ScopeCommit = internal.ScopeCommit
	ScopeStaged = internal.ScopeStaged
	ScopeFull   = internal.ScopeFull
)

func buildCLI(t *testing.T) string { t.Helper(); return os.Args[0] }

// Test-only process entry uses the real CLI run() with isolated TLS trust.
func TestCLIProcess(t *testing.T) {
	if os.Getenv("TLI_TEST_CHILD") != "1" {
		return
	}
	if path := os.Getenv("TLI_TEST_CA"); path != "" {
		data, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			t.Fatal("invalid fixture CA")
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		http.DefaultTransport = transport
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, flag.Args(), os.Stdin, os.Stdout, os.Stderr))
}
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	out, e := c.CombinedOutput()
	if e != nil {
		t.Fatalf("git: %v %s", e, out)
	}
	return strings.TrimSpace(string(out))
}
func sourceFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "remote", "add", "origin", "https://example.test/repo.git")
	os.WriteFile(filepath.Join(root, "a.txt"), []byte("a.txt"), 0600)
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "first")
	os.WriteFile(filepath.Join(root, "main.go"), []byte("committed"), 0600)
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "code")
	sha := runGit(t, root, "rev-parse", "HEAD")
	os.WriteFile(filepath.Join(root, "main.go"), []byte("indexed"), 0600)
	runGit(t, root, "add", "main.go")
	os.WriteFile(filepath.Join(root, "main.go"), []byte("working"), 0600)
	return root, sha
}
func testProcessEnv(t *testing.T, s *httptest.Server, temp string) []string {
	t.Helper()
	cert := filepath.Join(t.TempDir(), "ca.pem")
	if e := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	// Standard Go TLS trust configuration only; no InsecureSkipVerify or production bypass.
	env := append(os.Environ(), "HOME="+t.TempDir(), "TLI_API_ENDPOINT="+s.URL, "TLI_API_KEY=fixture-secret", "TLI_TEST_CHILD=1", "TLI_TEST_CA="+cert, "TMPDIR="+temp, "CI=true", "TLI_LOG_LEVEL=trace")
	return env
}
func TestCLIEndToEndLocalServer(t *testing.T) {
	bin := buildCLI(t)
	for _, tc := range []struct {
		scope          ScanScope
		state, content string
		complete       bool
		exit           int
	}{{ScopeCommit, "COMPLETED", "committed", true, 0}, {ScopeStaged, "FAILED", "indexed", true, 1}, {ScopeFull, "COMPLETED", "working", false, 1}} {
		t.Run(string(tc.scope), func(t *testing.T) {
			work, sha := sourceFixture(t)
			var starts atomic.Int32
			archive := map[string]string{}
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/cli-files":
					fmt.Fprintf(w, `{"presigned_urls":{"snapshot.tar.gz":%q}}`, server.URL+"/upload")
				case "/upload":
					if r.Header.Get("X-API-Key") != "" {
						t.Error("key leaked to PUT")
					}
					gz, e := gzip.NewReader(r.Body)
					if e != nil {
						t.Error(e)
						http.Error(w, "invalid gzip", 400)
						return
					}
					defer gz.Close()
					tr := tar.NewReader(gz)
					for {
						h, e := tr.Next()
						if e == io.EOF {
							break
						}
						if e != nil {
							t.Error(e)
							break
						}
						b, e := io.ReadAll(tr)
						if e != nil {
							t.Error(e)
						}
						archive[h.Name] = string(b)
					}
				case "/run-scan":
					starts.Add(1)
					fmt.Fprint(w, `{"scan_id":"scan-fixture"}`)
				case "/scan-status":
					fmt.Fprintf(w, `{"status":%q,"result":{"status":%q,"issues_count":2,"coverage":{"complete":%t,"errors":[]},"report_url":"https://report.test/result"}}`, tc.state, tc.state, tc.complete)
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			temp := t.TempDir()
			env := testProcessEnv(t, server, temp)
			args := []string{"scan", "--path", work, "--output", "json"}
			switch tc.scope {
			case ScopeCommit:
				args = append(args, "--commit", sha)
			case ScopeStaged:
				args = append(args, "--staged")
			case ScopeFull:
				args = append(args, "--full")
			}
			cmd := exec.Command(bin, append([]string{"-test.run=^TestCLIProcess$", "--"}, args...)...)
			cmd.Env = env
			var out, diagnostic bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &diagnostic
			e := cmd.Run()
			exit := 0
			if e != nil {
				ee, ok := e.(*exec.ExitError)
				if !ok {
					t.Fatal(e)
				}
				exit = ee.ExitCode()
			}
			if exit != tc.exit || !json.Valid(out.Bytes()) || starts.Load() != 1 {
				t.Fatalf("exit=%d starts=%d out=%s err=%s", exit, starts.Load(), out.String(), diagnostic.String())
			}
			if archive["main.go"] != tc.content {
				t.Fatalf("wrong snapshot: %v", archive)
			}
			wantFiles := 1
			if tc.scope == ScopeFull {
				wantFiles = 2
			}
			if len(archive) != wantFiles {
				t.Fatal(archive)
			}
			for _, s := range []string{out.String(), diagnostic.String()} {
				if strings.Contains(s, "fixture-secret") {
					t.Fatal("key in logs")
				}
			}
			entries, _ := os.ReadDir(temp)
			if len(entries) != 0 {
				t.Fatalf("temp leaked: %v", entries)
			}
		})
	}
}
func TestCLIInterruptDuringWait(t *testing.T) {
	if os.Getenv("GOOS") == "windows" {
		t.Skip("interrupt semantics differ")
	}
	bin := buildCLI(t)
	work, _ := sourceFixture(t)
	var server *httptest.Server
	waiting := make(chan struct{}, 1)
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli-files":
			fmt.Fprintf(w, `{"presigned_urls":{"snapshot.tar.gz":%q}}`, server.URL+"/upload")
		case "/upload":
			io.Copy(io.Discard, r.Body)
		case "/run-scan":
			fmt.Fprint(w, `{"scan_id":"scan-running"}`)
		case "/scan-status":
			select {
			case waiting <- struct{}{}:
			default:
			}
			fmt.Fprint(w, `{"status":"IN_PROGRESS"}`)
		}
	}))
	defer server.Close()
	temp := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-test.run=^TestCLIProcess$", "--", "scan", "--path", work, "--staged", "--output", "json")
	cmd.Env = testProcessEnv(t, server, temp)
	var out, diagnostic bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-waiting:
	case <-ctx.Done():
		t.Fatal("never started wait")
	}
	if e := cmd.Process.Signal(os.Interrupt); e != nil {
		t.Fatal(e)
	}
	e := cmd.Wait()
	var result internal.StatusResult
	if json.Unmarshal(out.Bytes(), &result) != nil || result.ScanID != "scan-running" {
		t.Fatalf("lost identity out=%s err=%s", out.String(), diagnostic.String())
	}
	if ee, ok := e.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
		t.Fatalf("exit=%v", e)
	}
	entries, _ := os.ReadDir(temp)
	if len(entries) != 0 {
		t.Fatalf("temp leaked: %v", entries)
	}
}
func TestCLIInvalidArgumentsProcess(t *testing.T) {
	bin := buildCLI(t)
	cmd := exec.Command(bin, "-test.run=^TestCLIProcess$", "--", "scan", "--output", "json", "--staged", "--commit", "HEAD")
	cmd.Env = append(os.Environ(), "TLI_TEST_CHILD=1")
	var out, diagnostic bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diagnostic
	e := cmd.Run()
	if ee, ok := e.(*exec.ExitError); !ok || ee.ExitCode() != 1 || out.Len() != 0 || diagnostic.Len() == 0 {
		t.Fatalf("e=%v out=%q err=%q", e, out.String(), diagnostic.String())
	}
}
