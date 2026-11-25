package internal

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type doFunc func(*http.Request) (*http.Response, error)

func (f doFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }
func TestClientTransportFailureNoPanic(t *testing.T) {
	c := APIClient{Config: Config{APIEndpoint: "https://fixture.test", APIKey: "secret"}, HTTP: doFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret transport") })}
	_, err := c.Status(context.Background(), "scan")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe/missing error: %v", err)
	}
}
func TestClientCancelsRequests(t *testing.T) {
	c := APIClient{Config: Config{APIEndpoint: "https://fixture.test"}, HTTP: doFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Status(ctx, "scan"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
func TestUploadOmitsAPIKey(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "" {
			t.Error("key leaked to storage")
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != "archive" {
			t.Errorf("body=%q", b)
		}
		w.WriteHeader(200)
	}))
	defer s.Close()
	p := filepath.Join(t.TempDir(), "archive")
	os.WriteFile(p, []byte("archive"), 0600)
	c := APIClient{Config: Config{APIKey: "secret"}, HTTP: s.Client()}
	if err := c.Upload(context.Background(), s.URL, p); err != nil {
		t.Fatal(err)
	}
}
func TestClientRefusesCrossOriginRedirect(t *testing.T) {
	reached := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer target.Close()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	c := APIClient{Config: Config{APIEndpoint: s.URL, APIKey: "secret"}, HTTP: s.Client()}
	if _, err := c.Start(context.Background(), RunScanInput{}); err == nil {
		t.Fatal("redirect accepted")
	}
	if reached {
		t.Fatal("redirect reached another origin")
	}
}
func TestClientInvalidJSON(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "not json") }))
	defer s.Close()
	c := APIClient{Config: Config{APIEndpoint: s.URL}, HTTP: s.Client()}
	if _, err := c.Status(context.Background(), "x"); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}
func TestLogsNeverExposeSecrets(t *testing.T) {
	c := APIClient{Config: Config{APIEndpoint: "https://user:secret@fixture.test?token=secret", APIKey: "secret"}}
	if _, err := c.Start(context.Background(), RunScanInput{}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("unsafe endpoint: %v", err)
	}
}
func TestStatusRequestTimeoutRetriesWithinGlobalDeadline(t *testing.T) {
	calls := 0
	c := APIClient{Config: Config{APIEndpoint: "https://fixture.test"}, APITimeout: time.Millisecond, HTTP: doFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"COMPLETED","result":{"status":"COMPLETED","coverage":{"complete":true}}}`))}, nil
	})}
	w := Waiter{Client: &c, Sleep: func(context.Context, time.Duration) error { return nil }}
	if _, e := w.Wait(context.Background(), "fixture", nil); e != nil || calls != 2 {
		t.Fatalf("requests=%d err=%v", calls, e)
	}
}
func TestClientTimeout(t *testing.T) {
	c := APIClient{Config: Config{APIEndpoint: "https://fixture.test"}, APITimeout: time.Millisecond, HTTP: doFunc(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })}
	if _, err := c.Status(context.Background(), "x"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout=%v", err)
	}
}
