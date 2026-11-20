package internal

import (
	"encoding/json"
	"sort"
)

type scanManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type scanManifest struct {
	Version    int                `json:"version"`
	Scope      ScanScope          `json:"scope"`
	Commit     string             `json:"commit"`
	Branch     string             `json:"branch"`
	FocusFiles []string           `json:"focus_files"`
	Files      []scanManifestFile `json:"files"`
}

func MarshalScanManifest(plan ScanPlan) ([]byte, error) {
	focus := append([]string(nil), plan.FocusFiles...)
	sort.Strings(focus)
	files := make([]scanManifestFile, 0, len(plan.Files))
	for _, f := range plan.Files {
		files = append(files, scanManifestFile{Path: f.Path, SHA256: f.SHA256, Size: f.Size})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return json.Marshal(scanManifest{
		Version:    1,
		Scope:      plan.Scope,
		Commit:     plan.Repository.Commit,
		Branch:     plan.Repository.Branch,
		FocusFiles: focus,
		Files:      files,
	})
}
