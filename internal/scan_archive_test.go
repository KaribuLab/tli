package internal

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type policyRoundTripper func(*http.Request) (*http.Response, error)

func (f policyRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestPolicyArchiveTransport(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("TLI_API_KEY", "test-key")
	t.Setenv("TLI_API_ENDPOINT", "https://api.invalid")
	for name, content := range map[string]string{"main.go": "working tree source", ".titvoignore.yml": "version: 1\nexceptions: []\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := collectScanFiles([]string{filepath.Join(root, "main.go"), filepath.Join(root, ".titvoignore.yml")}, root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, f := range files {
			f.File.Close()
		}
	}()
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	uploaded := false
	http.DefaultTransport = policyRoundTripper(func(r *http.Request) (*http.Response, error) {
		body := ""
		if r.Method == "POST" {
			var req struct {
				Args struct {
					Files []struct {
						Name string `json:"name"`
					} `json:"files"`
					Original []string `json:"original_files"`
				} `json:"args"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			want := []string{filepath.Join(root, ".titvoignore.yml"), filepath.Join(root, "main.go")}
			if !reflect.DeepEqual(req.Args.Original, want) {
				t.Fatalf("manifest=%v", req.Args.Original)
			}
			raw, _ := json.Marshal(map[string]any{"presigned_urls": map[string]string{req.Args.Files[0].Name: "https://upload.invalid/archive"}})
			body = string(raw)
		} else {
			gz, e := gzip.NewReader(r.Body)
			if e != nil {
				t.Fatal(e)
			}
			defer gz.Close()
			tr := tar.NewReader(gz)
			got := map[string]string{}
			for {
				h, e := tr.Next()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatal(e)
				}
				if _, ok := got[h.Name]; ok {
					t.Fatal("duplicate entry")
				}
				data, e := io.ReadAll(tr)
				if e != nil {
					t.Fatal(e)
				}
				got[h.Name] = string(data)
			}
			want := map[string]string{"main.go": "working tree source", ".titvoignore.yml": "version: 1\nexceptions: []\n"}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("archive=%v", got)
			}
			uploaded = true
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	if err := UploadFilesAsGzip(&UploadFilesAsGzipInput{BatchId: "test", Files: files}); err != nil {
		t.Fatal(err)
	}
	if !uploaded {
		t.Fatal("no archive uploaded")
	}
}
