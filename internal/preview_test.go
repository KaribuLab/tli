package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestPreviewOfflineJSON(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TLI_API_KEY", "")
	t.Setenv("TLI_API_ENDPOINT", "")
	work, _ := sourceFixture(t)
	cmd := NewPreviewCommand(ScanService{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--path", work, "--staged", "--output", "json"})
	if e := cmd.Execute(); e != nil {
		t.Fatal(e)
	}
	var p ScanPlan
	if e := json.Unmarshal(out.Bytes(), &p); e != nil {
		t.Fatal(e)
	}
	assertPlanContent(t, p, "main.go", "indexed")
}
func TestExplicitScopeConflicts(t *testing.T) {
	for _, args := range [][]string{{"--commit", "HEAD", "--staged"}, {"--full", "--commit", "HEAD"}, {"--full", "--staged"}} {
		cmd := NewPreviewCommand(ScanService{})
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if e := cmd.Execute(); e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
func TestInvalidOutputRejectedBeforeNetwork(t *testing.T) {
	s, requests, _ := testService(t, false)
	cmd := newScanCommand(s)
	cmd.SetArgs([]string{"--output", "bad"})
	if e := cmd.Execute(); e == nil || *requests != 0 {
		t.Fatal("invalid format triggered scan")
	}
}
func TestPreviewReportsExclusionReasons(t *testing.T) {
	_, work := newRepoWithRemote(t)
	fixtureWrite(t, work, ".env", "secret")
	runGit(t, work, "add", ".")
	p, e := (Planner{}).Plan(context.Background(), optionsFor(work, ScopeFull))
	if e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e = WritePlan(&out, p, "markdown"); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "sensitive") || !strings.Contains(out.String(), ".env") {
		t.Fatal(out.String())
	}
}
func TestScanCLIUsesPathAndLimitOverrides(t *testing.T) {
	work, _ := sourceFixture(t)
	s, requests, _ := testService(t, false)
	cmd := newScanCommand(s)
	cmd.SetArgs([]string{"--path", work, "--staged", "--max-file-bytes", "3"})
	if e := cmd.Execute(); e == nil || *requests != 0 {
		t.Fatal("limit ignored or scan started")
	}
}
func TestScanJSONSingleObject(t *testing.T) {
	for _, status := range []string{"FAILED", "COMPLETED"} {
		work, _ := sourceFixture(t)
		s, _, _ := testService(t, false)
		r := terminalFixture(status)
		if status == "COMPLETED" {
			r.Result.Result.Coverage = nil
		}
		s.Wait.Client = statusFunc(func(context.Context, string) (GetScanStatusOutput, error) { return r, nil })
		cmd := newScanCommand(s)
		cmd.SetArgs([]string{"--path", work, "--staged", "--output", "json"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		if e := cmd.Execute(); e == nil {
			t.Fatal("findings/incomplete should fail")
		}
		dec := json.NewDecoder(&out)
		var result StatusResult
		if e := dec.Decode(&result); e != nil {
			t.Fatal(e)
		}
		var extra any
		if e := dec.Decode(&extra); e != io.EOF {
			t.Fatalf("contaminated: %v", e)
		}
		if result.ScanID != "scan-fixture" {
			t.Fatal(result)
		}
	}
}
func TestGitHookURLOnly(t *testing.T) {
	work, _ := sourceFixture(t)
	s, _, _ := testService(t, false)
	cmd := newScanCommand(s)
	cmd.SetArgs([]string{"--path", work, "--staged", "--githook"})
	var out bytes.Buffer
	cmd.SetOut(&out)
	if e := cmd.Execute(); e != nil {
		t.Fatal(e)
	}
	if out.String() != "https://report.test/fixture\n" {
		t.Fatal(out.String())
	}
}
func TestMarkdownFindings(t *testing.T) {
	r := StatusResult{ScanID: "fixture", ReportUrl: "https://report.test", Result: ScanResult{Status: "FAILED", Annotations: []Annotation{{Title: "injection", Description: "untrusted input", Path: "main.go", Line: 9, Recommendation: "validate input"}}}}
	var out bytes.Buffer
	if e := WriteResult(&out, r, "markdown", false); e != nil {
		t.Fatal(e)
	}
	for _, word := range []string{"injection", "untrusted input", "main.go", "9", "validate input", "https://report.test"} {
		if !strings.Contains(out.String(), word) {
			t.Fatalf("missing %q", word)
		}
	}
}
