package internal

import (
	"bytes"
	"errors"
	"testing"
)

func TestExitCode(t *testing.T) {
	if ExitCode(nil) != 0 {
		t.Fatal("success must exit zero")
	}
	for _, kind := range []string{"findings", "technical", "incomplete", "cancelled"} {
		if ExitCode(&ScanError{Kind: kind, Err: errors.New("fixture")}) != 1 {
			t.Fatalf("%s must fail", kind)
		}
	}
}
func TestScanInvalidFlagsReturnsError(t *testing.T) {
	cmd := NewScanCommand()
	var out, diagnostic bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&diagnostic)
	cmd.SetArgs([]string{"--commit", "HEAD", "--staged"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("incompatible modes must fail before Git/network")
	}
	if out.Len() != 0 {
		t.Fatalf("stdout contaminated: %q", out.String())
	}
}
