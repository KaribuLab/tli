package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func testService(t *testing.T, failUpload bool) (ScanService, *int, *int) {
	t.Helper()
	requests, starts := 0, 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/cli-files":
			var body struct {
				Args struct {
					Files []struct {
						Name string `json:"name"`
					} `json:"files"`
				} `json:"args"`
			}
			if e := json.NewDecoder(r.Body).Decode(&body); e != nil {
				t.Error(e)
			}
			if len(body.Args.Files) != 1 {
				t.Fatal("missing archive")
			}
			json.NewEncoder(w).Encode(map[string]any{"presigned_urls": map[string]string{body.Args.Files[0].Name: server.URL + "/upload"}})
		case "/upload":
			if failUpload {
				http.Error(w, "fixture failure", 500)
				return
			}
			if r.Header.Get("X-API-Key") != "" {
				t.Error("storage key leak")
			}
			io.Copy(io.Discard, r.Body)
		case "/run-scan":
			starts++
			fmt.Fprint(w, `{"scan_id":"scan-fixture"}`)
		case "/scan-status":
			fmt.Fprint(w, `{"status":"COMPLETED","result":{"status":"COMPLETED","coverage":{"complete":true},"report_url":"https://report.test/fixture"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	service := ScanService{API: &APIClient{Config: Config{APIEndpoint: server.URL, APIKey: "fixture"}, HTTP: server.Client()}}
	return service, &requests, &starts
}
func TestServicePreviewNeverLoadsConfigOrNetwork(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TLI_API_KEY", "")
	t.Setenv("TLI_API_ENDPOINT", "")
	work, _ := sourceFixture(t)
	s, requests, _ := testService(t, false)
	if _, e := s.Preview(context.Background(), optionsFor(work, ScopeFull)); e != nil {
		t.Fatal(e)
	}
	if *requests != 0 {
		t.Fatal("preview contacted service")
	}
}
func TestServiceReconfirmationBeforeUpload(t *testing.T) {
	work, _ := sourceFixture(t)
	s, requests, _ := testService(t, false)
	o := optionsFor(work, ScopeFull)
	plan, e := s.Preview(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	fixtureWrite(t, work, "main.go", "different")
	_, e = s.Scan(context.Background(), o, plan.Fingerprint, nil)
	var se *ScanError
	if !errors.As(e, &se) || se.Kind != "plan-changed" || *requests != 0 {
		t.Fatalf("requests=%d err=%v", *requests, e)
	}
}
func TestServiceUploadsOnceAndCleans(t *testing.T) {
	work, _ := sourceFixture(t)
	s, requests, starts := testService(t, false)
	temp := t.TempDir()
	s.Snapshots.TempRoot = temp
	r, e := s.Scan(context.Background(), optionsFor(work, ScopeStaged), "", nil)
	if e != nil || r.ScanID != "scan-fixture" || *starts != 1 || *requests != 4 {
		t.Fatalf("r=%+v err=%v req=%d starts=%d", r, e, *requests, *starts)
	}
	files, _ := os.ReadDir(temp)
	if len(files) > 0 {
		t.Fatal("snapshot leaked")
	}
}
func TestServiceFailureBeforeStartDoesNotCreateScan(t *testing.T) {
	work, _ := sourceFixture(t)
	s, _, starts := testService(t, true)
	if _, e := s.Scan(context.Background(), optionsFor(work, ScopeStaged), "", nil); e == nil || *starts != 0 {
		t.Fatal("task started despite failed upload")
	}
}
func TestServiceProgressIsFactual(t *testing.T) {
	work, _ := sourceFixture(t)
	s, _, _ := testService(t, false)
	var phases []string
	_, e := s.Scan(context.Background(), optionsFor(work, ScopeStaged), "", func(p ProgressEvent) {
		phases = append(phases, p.Phase)
		if (p.Phase == "preparing" || p.Phase == "uploading") && p.ScanID != "" {
			t.Error("scan id invented before start")
		}
	})
	if e != nil {
		t.Fatal(e)
	}
	if fmt.Sprint(phases) != "[preparing uploading analyzing completed]" {
		t.Fatalf("phases=%v", phases)
	}
}
