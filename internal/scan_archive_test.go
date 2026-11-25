package internal

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestPolicyArchiveTransport(t *testing.T) {
	_, root := newRepoWithRemote(t)
	fixtureWrite(t, root, "main.go", "working tree source")
	fixtureWrite(t, root, ".titvoignore.yml", "version: 1\nexceptions: []\n")
	runGit(t, root, "add", "main.go", ".titvoignore.yml")
	uploads, starts := 0, 0
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cli-files":
			var req struct {
				Args struct {
					Files []struct {
						Name string `json:"name"`
					} `json:"files"`
					Original []string `json:"original_files"`
				} `json:"args"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			if !reflect.DeepEqual(req.Args.Original, []string{".titvoignore.yml", "a.txt", "main.go"}) {
				t.Errorf("original_files=%v", req.Args.Original)
			}
			urls := map[string]string{}
			for _, f := range req.Args.Files {
				urls[f.Name] = server.URL + "/upload/" + f.Name
			}
			if len(urls) != 2 {
				t.Errorf("uploads=%v", urls)
			}
			json.NewEncoder(w).Encode(map[string]any{"presigned_urls": urls})
		case "/upload/snapshot.tar.gz":
			uploads++
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			defer gz.Close()
			tr := tar.NewReader(gz)
			got := map[string]string{}
			for {
				h, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Error(err)
					return
				}
				if _, ok := got[h.Name]; ok {
					t.Error("duplicate archive entry")
				}
				b, err := io.ReadAll(tr)
				if err != nil {
					t.Error(err)
					return
				}
				got[h.Name] = string(b)
			}
			want := map[string]string{"a.txt": "a.txt", "main.go": "working tree source", ".titvoignore.yml": "version: 1\nexceptions: []\n"}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("archive=%v", got)
			}
		case "/upload/" + ScanManifestName:
			uploads++
			var m struct {
				Files []struct{ Path string }
				Focus []string `json:"focus_files"`
			}
			if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
				t.Error(err)
			}
			count := 0
			for _, f := range m.Files {
				if f.Path == ".titvoignore.yml" {
					count++
				}
			}
			if count != 1 || !reflect.DeepEqual(m.Focus, []string{"main.go"}) {
				t.Errorf("manifest=%+v", m)
			}
		case "/run-scan":
			starts++
			fmt.Fprint(w, `{"scan_id":"policy-fixture"}`)
		case "/scan-status":
			fmt.Fprint(w, `{"status":"COMPLETED","result":{"status":"COMPLETED","coverage":{"complete":true}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	service := ScanService{API: &APIClient{Config: Config{APIEndpoint: server.URL, APIKey: "fixture"}, HTTP: server.Client()}}
	result, err := service.Scan(context.Background(), optionsFor(root, ScopeStaged), "", nil)
	if err != nil || result.ScanID != "policy-fixture" || uploads != 2 || starts != 1 {
		t.Fatalf("result=%+v error=%v uploads=%d starts=%d", result, err, uploads, starts)
	}
}
