package internal

import (
	"context"
	"errors"
	"testing"
	"time"
)

type statusFunc func(context.Context, string) (GetScanStatusOutput, error)

func (f statusFunc) Status(ctx context.Context, id string) (GetScanStatusOutput, error) {
	return f(ctx, id)
}
func terminalFixture(state string) GetScanStatusOutput {
	return GetScanStatusOutput{Status: state, Result: StatusResult{ScanID: "scan-fixture", Result: ScanResult{Status: state, Coverage: &ScanCoverage{Complete: true}}}}
}
func TestWaitTerminalStates(t *testing.T) {
	for _, state := range []string{"COMPLETED", "FAILED", "WARNING", "ERROR"} {
		t.Run(state, func(t *testing.T) {
			calls := 0
			w := Waiter{Client: statusFunc(func(context.Context, string) (GetScanStatusOutput, error) {
				calls++
				return terminalFixture(state), nil
			})}
			result, err := w.Wait(context.Background(), "scan-fixture", nil)
			if calls != 1 || (err == nil) != (state == "COMPLETED") || result.ScanID != "scan-fixture" {
				t.Fatalf("calls=%d result=%+v err=%v", calls, result, err)
			}
		})
	}
}
func TestWaitMissingCoverageFails(t *testing.T) {
	r := terminalFixture("COMPLETED")
	r.Result.Result.Coverage = nil
	w := Waiter{Client: statusFunc(func(context.Context, string) (GetScanStatusOutput, error) { return r, nil })}
	result, err := w.Wait(context.Background(), "scan-fixture", nil)
	var se *ScanError
	if !errors.As(err, &se) || se.Kind != "incomplete" || result.ScanID != "scan-fixture" {
		t.Fatalf("%+v %v", result, err)
	}
}
func TestWaitCancelAndTimeout(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		if deadline {
			var c context.CancelFunc
			ctx, c = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			defer c()
		} else {
			cancel()
		}
		defer cancel()
		w := Waiter{Client: statusFunc(func(context.Context, string) (GetScanStatusOutput, error) {
			t.Fatal("request after cancellation")
			return GetScanStatusOutput{}, nil
		})}
		if _, err := w.Wait(ctx, "scan-fixture", nil); err == nil {
			t.Fatal("cancel ignored")
		}
	}
}
func TestWaitRetryBudget(t *testing.T) {
	calls := 0
	sleeps := 0
	w := Waiter{Client: statusFunc(func(context.Context, string) (GetScanStatusOutput, error) {
		calls++
		return GetScanStatusOutput{}, &APIError{Retryable: true, RetryAfter: 7 * time.Second}
	}), MaxTransientRetries: 3, Sleep: func(ctx context.Context, d time.Duration) error {
		if d != 7*time.Second {
			t.Errorf("retry delay=%v", d)
		}
		sleeps++
		return nil
	}}
	if _, err := w.Wait(context.Background(), "scan-fixture", nil); err == nil || calls != 4 || sleeps != 3 {
		t.Fatalf("calls=%d sleeps=%d err=%v", calls, sleeps, err)
	}
}
func TestWaitHonorsCallerDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	want, _ := ctx.Deadline()
	w := Waiter{Client: statusFunc(func(c context.Context, _ string) (GetScanStatusOutput, error) {
		got, _ := c.Deadline()
		if !got.Equal(want) {
			t.Fatalf("caller deadline shortened: %v -> %v", want, got)
		}
		return terminalFixture("COMPLETED"), nil
	})}
	if _, e := w.Wait(ctx, "fixture", nil); e != nil {
		t.Fatal(e)
	}
}
func TestReportPreservedOnFindings(t *testing.T) {
	r := terminalFixture("FAILED")
	r.Result.Result.NumberOfIssues = 3
	w := Waiter{Client: statusFunc(func(context.Context, string) (GetScanStatusOutput, error) { return r, nil })}
	result, err := w.Wait(context.Background(), "scan-fixture", nil)
	var se *ScanError
	if !errors.As(err, &se) || se.Kind != "findings" || result.Result.NumberOfIssues != 3 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
