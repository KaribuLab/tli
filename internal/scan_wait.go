package internal

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

var scanIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func validScanID(id string) bool { return scanIDPattern.MatchString(id) }

type StatusReader interface {
	Status(context.Context, string) (GetScanStatusOutput, error)
}
type Waiter struct {
	Client              StatusReader
	Interval            time.Duration
	MaxTransientRetries int
	Sleep               func(context.Context, time.Duration) error
	Now                 func() time.Time
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (w Waiter) Wait(ctx context.Context, id string, progress ProgressSink) (StatusResult, error) {
	result := StatusResult{ScanID: id}
	if !validScanID(id) || w.Client == nil {
		return result, fmt.Errorf("espera no válida")
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Hour)
		defer cancel()
	}
	if w.Sleep == nil {
		w.Sleep = sleepContext
	}
	if w.Now == nil {
		w.Now = time.Now
	}
	if w.Interval <= 0 {
		w.Interval = 5 * time.Second
	}
	if w.MaxTransientRetries <= 0 {
		w.MaxTransientRetries = 3
	}
	started := w.Now()
	retries := 0
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		status, err := w.Client.Status(ctx, id)
		if err != nil {
			var apiErr *APIError
			if !errors.As(err, &apiErr) || !apiErr.Retryable || retries >= w.MaxTransientRetries {
				return result, err
			}
			retries++
			delay := w.Interval
			if apiErr.RetryAfter > delay {
				delay = apiErr.RetryAfter
			}
			if err = w.Sleep(ctx, delay); err != nil {
				return result, err
			}
			continue
		}
		retries = 0
		switch status.Status {
		case "COMPLETED", "FAILED", "WARNING", "ERROR":
			result = status.Result
			result.ScanID = id
			if status.Status == "ERROR" {
				return result, &ScanError{Kind: "technical", Err: fmt.Errorf("el servicio devolvió ERROR")}
			}
			if err := ValidateResult(result); err != nil {
				return result, err
			}
			if status.Status == "FAILED" || status.Status == "WARNING" {
				return result, &ScanError{Kind: "findings", Err: fmt.Errorf("análisis con hallazgos")}
			}
			return result, nil
		case "IN_PROGRESS", "PENDING", "QUEUED", "RUNNING", "STARTED":
		default:
			return result, &ScanError{Kind: "technical", Err: fmt.Errorf("estado remoto desconocido")}
		}
		if progress != nil {
			progress(ProgressEvent{Phase: "analyzing", ScanID: id, Elapsed: w.Now().Sub(started)})
		}
		if err = w.Sleep(ctx, w.Interval); err != nil {
			return result, err
		}
	}
}
func ValidateResult(r StatusResult) error {
	fail := func(kind, message string) error { return &ScanError{Kind: kind, Err: errors.New(message)} }
	if !validScanID(r.ScanID) {
		return fail("technical", "scan_id no válido")
	}
	if r.Result.Error != nil && r.Result.Error != "" && r.Result.Error != false {
		return fail("technical", "el servicio declaró un error técnico")
	}
	if r.Result.Incomplete != nil || r.Result.Coverage == nil || !r.Result.Coverage.Complete || len(r.Result.Coverage.Errors) > 0 {
		return fail("incomplete", "cobertura incompleta o no registrada")
	}
	switch r.Result.Status {
	case "COMPLETED":
		return nil
	case "FAILED", "WARNING":
		return fail("findings", "análisis con hallazgos")
	default:
		return fail("technical", "estado de resultado no válido")
	}
}
