package internal

import (
	"context"
	"errors"
	"testing"
)

func inlineFixture() InlineModel {
	m := NewInlineModel(ScanOptions{Path: ".", Limits: DefaultLimits()}, RepositoryIdentity{Root: "demo", Branch: "main", URL: "https://example.test/repo"}, nil, 96, 28)
	m, _ = UpdateInline(m, InlineEvent{Kind: "geometry-ready", Width: 96, Height: 28})
	return m
}
func inlineKey(m InlineModel, key string) (InlineModel, InlineEffect) {
	return UpdateInline(m, InlineEvent{Kind: "key", Key: key})
}
func inlinePreview(t *testing.T) InlineModel {
	t.Helper()
	m, e := inlineKey(inlineFixture(), "enter")
	if e.Kind != "preview" {
		t.Fatal(e)
	}
	plan := ScanPlan{Scope: ScopeStaged, Files: []PlannedFile{{Path: "main.go", Size: 3}}, TotalBytes: 3, Fingerprint: "exact"}
	m, _ = UpdateInline(m, InlineEvent{Kind: "preview-done", Revision: e.Revision, Plan: &plan})
	return m
}
func TestInlineActionsDefaultAndFilter(t *testing.T) {
	m := inlineFixture()
	actions := InlineActions(m)
	for i, id := range []string{"staged", "commit", "full", "preview", "setup", "quit"} {
		if actions[i].ID != id {
			t.Fatal(actions)
		}
	}
	got := FilterInlineActions(actions, "conexion")
	if len(got) != 1 || got[0].ID != "setup" {
		t.Fatal(got)
	}
	m, _ = inlineKey(m, "q")
	if m.Query != "q" {
		t.Fatal("q became exit")
	}
	m, e := inlineKey(m, "enter")
	if e.Kind != "" {
		t.Fatal("no-match filter activated an action")
	}
	m, _ = inlineKey(m, "backspace")
	if m.Query != "" {
		t.Fatal(m.Query)
	}
}
func TestInlinePreviewOnlyAndCommit(t *testing.T) {
	m := inlineFixture()
	m.Selection = 3
	m, _ = inlineKey(m, "enter")
	if m.Stage != "scope" || !m.PreviewOnly {
		t.Fatal(m)
	}
	m, e := inlineKey(m, "enter")
	if e.Kind != "preview" || m.Options.Scope != ScopeStaged {
		t.Fatal(m, e)
	}
	plan := ScanPlan{Files: []PlannedFile{{Path: "a"}}, Fingerprint: "p"}
	m, _ = UpdateInline(m, InlineEvent{Kind: "preview-done", Revision: e.Revision, Plan: &plan})
	m, e = inlineKey(m, "enter")
	if e.Kind == "scan" || m.Stage != "files" {
		t.Fatal(m, e)
	}
	m = inlineFixture()
	m.Selection = 1
	m, _ = inlineKey(m, "enter")
	if m.Stage != "commit" || m.DraftCommit != "HEAD" {
		t.Fatal(m)
	}
	m, _ = inlineKey(m, "q")
	if m.DraftCommit != "HEADq" {
		t.Fatal(m.DraftCommit)
	}
}
func TestInlineConfirmationDefaultBack(t *testing.T) {
	m := inlinePreview(t)
	if m.Stage != "confirm" || m.Selection != 0 {
		t.Fatal(m)
	}
	m, e := inlineKey(m, "enter")
	if e.Kind != "" || m.Stage != "actions" {
		t.Fatal("implicit upload", m, e)
	}
}
func TestInlineDropsStaleEvents(t *testing.T) {
	m := inlinePreview(t)
	for _, kind := range []string{"preview-done", "scan-done", "progress"} {
		got, e := UpdateInline(m, InlineEvent{Kind: kind, Revision: m.Revision - 1, Progress: ProgressEvent{ScanID: "old"}})
		if got.Stage != m.Stage || got.Progress.ScanID == "old" || e.Kind != "" {
			t.Fatal(got, e)
		}
	}
}
func TestInlineCancelKeepsIdentity(t *testing.T) {
	m := inlineFixture()
	m.Busy = true
	m.Stage = "running"
	m.Revision = 4
	m.Progress.ScanID = "scan-running"
	m, e := inlineKey(m, "ctrl+c")
	if e.Kind != "cancel" || !m.ExitRequested {
		t.Fatal(m, e)
	}
	m, e = UpdateInline(m, InlineEvent{Kind: "scan-done", Revision: 4, Err: context.Canceled})
	if e.Kind != "exit" || m.Result == nil || m.Result.ScanID != "scan-running" {
		t.Fatal(m, e)
	}
}
func TestInlineResizeInvalidatesConsent(t *testing.T) {
	m := inlinePreview(t)
	m.Selection = 1
	m.GeometryReady = true
	m, e := UpdateInline(m, InlineEvent{Kind: "resize", Width: 40, Height: 10})
	if e.Kind != "" || m.GeometryReady || m.Selection != 0 {
		t.Fatal(m, e)
	}
	m, e = inlineKey(m, "enter")
	if e.Kind == "scan" {
		t.Fatal("resize uploaded")
	}
}
func TestInlineChangedPlanRequiresNewPreview(t *testing.T) {
	m := inlineFixture()
	m.Stage = "running"
	m.Busy = true
	m.Revision = 4
	m, e := UpdateInline(m, InlineEvent{Kind: "scan-done", Revision: 4, Err: &ScanError{Kind: "plan-changed", Err: errors.New("changed")}})
	if e.Kind != "preview" || m.Revision != 5 || m.Plan != nil {
		t.Fatal(m, e)
	}
}
