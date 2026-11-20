package internal

import (
	"encoding/json"
	"testing"
)

func TestMarshalScanManifest(t *testing.T) {
	plan := ScanPlan{
		Repository: RepositoryIdentity{Commit: "abc", Branch: "main"},
		Scope:      ScopeCommit,
		FocusFiles: []string{"b.go", "a.go"},
		Files: []PlannedFile{
			{Path: "b.go", SHA256: "bb", Size: 2},
			{Path: "a.go", SHA256: "aa", Size: 1},
		},
	}
	raw, e := MarshalScanManifest(plan)
	if e != nil {
		t.Fatal(e)
	}
	var man scanManifest
	if e := json.Unmarshal(raw, &man); e != nil {
		t.Fatal(e)
	}
	if man.Version != 1 || man.Scope != ScopeCommit || man.Commit != "abc" || man.Branch != "main" {
		t.Fatalf("%+v", man)
	}
	if len(man.FocusFiles) != 2 || man.FocusFiles[0] != "a.go" || man.FocusFiles[1] != "b.go" {
		t.Fatalf("focus=%v", man.FocusFiles)
	}
	if len(man.Files) != 2 || man.Files[0].Path != "a.go" || man.Files[1].Path != "b.go" {
		t.Fatalf("files=%+v", man.Files)
	}
}
