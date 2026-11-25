package internal

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

type menuFixture struct {
	Scans, Previews int
	Options         ScanOptions
	OnScan          func() (StatusResult, error)
}

func (f *menuFixture) Preview(ctx context.Context, o ScanOptions) (ScanPlan, error) {
	f.Previews++
	f.Options = o
	return ScanPlan{Repository: RepositoryIdentity{URL: "https://example.test/repo"}, Files: []PlannedFile{{Path: "main.go", Size: 3}}, TotalBytes: 3, Fingerprint: "confirmed"}, nil
}
func (f *menuFixture) Scan(ctx context.Context, o ScanOptions, fingerprint string, p ProgressSink) (StatusResult, error) {
	if fingerprint != "confirmed" {
		return StatusResult{}, errors.New("missing confirmation fingerprint")
	}
	f.Scans++
	if f.OnScan != nil {
		return f.OnScan()
	}
	return terminalFixture("COMPLETED").Result, nil
}
func runMenuFixture(t *testing.T, input string, f *menuFixture, setup func(context.Context) error) (string, string, error) {
	t.Helper()
	var out, diagnostic bytes.Buffer
	m := Menu{In: strings.NewReader(input), Out: &out, Err: &diagnostic, Terminal: TerminalOptions{Interactive: true}, Service: f, Setup: setup, Defaults: ScanOptions{Path: ".", Scope: ScopeFull, Limits: DefaultLimits()}}
	e := m.Run(context.Background())
	return out.String(), diagnostic.String(), e
}
func TestMenuExitInvalidInputAndEOF(t *testing.T) {
	for _, input := range []string{"", "4\n", "invalid\n4\n"} {
		f := &menuFixture{}
		_, _, e := runMenuFixture(t, input, f, nil)
		if e != nil || f.Scans != 0 || f.Previews != 0 {
			t.Fatalf("input=%q err=%v", input, e)
		}
	}
}
func TestMenuDefaultDeclinesUpload(t *testing.T) {
	f := &menuFixture{}
	out, _, e := runMenuFixture(t, "1\n1\n\n4\n", f, nil)
	if e != nil || f.Scans != 0 || !strings.Contains(out, "[s/N]") {
		t.Fatalf("out=%s err=%v scans=%d", out, e, f.Scans)
	}
}
func TestMenuScanCommitFullStaged(t *testing.T) {
	for _, tc := range []struct {
		input string
		scope ScanScope
	}{{"1\n1\ns\n4\n", ScopeFull}, {"1\n2\n\ns\n4\n", ScopeCommit}, {"1\n3\ns\n4\n", ScopeStaged}} {
		f := &menuFixture{}
		out, _, e := runMenuFixture(t, tc.input, f, nil)
		if e != nil || f.Scans != 1 || f.Previews != 1 || f.Options.Scope != tc.scope || !strings.Contains(out, "main.go") {
			t.Fatalf("fixture=%+v out=%s err=%v", f, out, e)
		}
		if tc.scope == ScopeCommit && f.Options.Commit != "HEAD" {
			t.Fatal("HEAD default missing")
		}
	}
}
func TestMenuPreviewNeverScans(t *testing.T) {
	f := &menuFixture{}
	_, _, e := runMenuFixture(t, "2\n1\n4\n", f, nil)
	if e != nil || f.Scans != 0 || f.Previews != 1 {
		t.Fatal(f, e)
	}
}
func TestMenuSetupOnlyExplicit(t *testing.T) {
	calls := 0
	f := &menuFixture{}
	_, _, e := runMenuFixture(t, "3\n4\n", f, func(context.Context) error { calls++; return nil })
	if e != nil || calls != 1 || f.Scans != 0 {
		t.Fatal(e, calls)
	}
}
func TestMenuPlanChangedRequiresReconfirmation(t *testing.T) {
	f := &menuFixture{}
	f.OnScan = func() (StatusResult, error) {
		return StatusResult{}, &ScanError{Kind: "plan-changed", Err: errors.New("changed")}
	}
	_, _, e := runMenuFixture(t, "1\n1\ns\nn\n4\n", f, nil)
	if e != nil || f.Scans != 1 || f.Previews != 2 {
		t.Fatalf("f=%+v e=%v", f, e)
	}
}
func TestMenuCancelRetainsScanID(t *testing.T) {
	f := &menuFixture{OnScan: func() (StatusResult, error) { return StatusResult{ScanID: "scan-running"}, context.Canceled }}
	_, diagnostic, e := runMenuFixture(t, "1\n1\ns\n", f, nil)
	if !errors.Is(e, context.Canceled) || !strings.Contains(diagnostic, "scan-running") || !strings.Contains(diagnostic, "continuar") {
		t.Fatalf("e=%v diagnostic=%s", e, diagnostic)
	}
}
func TestMenuCredentialsMissingOffersSetup(t *testing.T) {
	calls := 0
	f := &menuFixture{OnScan: func() (StatusResult, error) { return StatusResult{}, ErrCredentials }}
	out, _, e := runMenuFixture(t, "1\n1\ns\n\n4\n", f, func(context.Context) error { calls++; return nil })
	if e != nil || calls != 0 || !strings.Contains(out, "configurar") {
		t.Fatalf("out=%s err=%v setup=%d", out, e, calls)
	}
}
