package internal

import (
	"fmt"
	"time"
)

type ScanScope string

const (
	ScopeFull   ScanScope = "full"
	ScopeCommit ScanScope = "commit"
	ScopeStaged ScanScope = "staged"
)

type Limits struct {
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFiles      int
}
type ScanOptions struct {
	Path, Remote, Commit string
	Scope                ScanScope
	Limits               Limits
	Timeout              time.Duration
}
type RepositoryIdentity struct{ Root, URL, Branch, Commit string }
type PlannedFile struct {
	Path, BlobOID, SHA256 string
	Size                  int64
}
type ExcludedFile struct{ Path, Reason string }
type ScanPlan struct {
	Repository  RepositoryIdentity
	Scope       ScanScope
	Files       []PlannedFile
	Excluded    []ExcludedFile
	TotalBytes  int64
	Fingerprint string
}
type ProgressEvent struct {
	Phase, ScanID string
	Files         int
	Bytes         int64
	Elapsed       time.Duration
}
type ProgressSink func(ProgressEvent)
type ScanError struct {
	Kind string
	Err  error
}

func (e *ScanError) Error() string { return fmt.Sprintf("%s: %v", e.Kind, e.Err) }
func (e *ScanError) Unwrap() error { return e.Err }
func ExitCode(err error) int {
	if err != nil {
		return 1
	}
	return 0
}
