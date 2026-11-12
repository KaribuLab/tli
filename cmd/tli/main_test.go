package main

import (
	"bytes"
	"context"
	"github.com/KaribuLab/tli/internal"
	"strings"
	"testing"
)

func TestMenuTerminalOnlyRoot(t *testing.T) {
	var out, diagnostic bytes.Buffer
	root := rootWithTerminal(internal.TerminalOptions{Interactive: true})
	root.SetIn(strings.NewReader("4\n"))
	root.SetOut(&out)
	root.SetErr(&diagnostic)
	root.SetArgs([]string{})
	if e := root.ExecuteContext(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "TITVO") || !strings.Contains(out.String(), "Escanear") {
		t.Fatal("interactive root did not open menu")
	}
	out.Reset()
	if code := run(context.Background(), nil, strings.NewReader(""), &out, &diagnostic); code != 0 || !strings.Contains(out.String(), "Usage:") {
		t.Fatal("redirected root should show help")
	}
}
func TestHelpVersionDoNotLoadConfig(t *testing.T) { TestRootHelpAndVersion(t) }
func TestRootHelpAndVersion(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--version"}} {
		var out, diagnostic bytes.Buffer
		if code := run(context.Background(), args, strings.NewReader(""), &out, &diagnostic); code != 0 {
			t.Fatalf("%v exit %d: %s", args, code, diagnostic.String())
		}
		if out.Len() == 0 || diagnostic.Len() != 0 {
			t.Fatalf("out=%q err=%q", out.String(), diagnostic.String())
		}
	}
}
func TestInvalidJSONArguments(t *testing.T) {
	var out, diagnostic bytes.Buffer
	code := run(context.Background(), []string{"scan", "--output", "json", "--commit", "HEAD", "--staged"}, strings.NewReader(""), &out, &diagnostic)
	if code != 1 || out.Len() != 0 || diagnostic.Len() == 0 {
		t.Fatalf("exit=%d out=%q err=%q", code, out.String(), diagnostic.String())
	}
}
