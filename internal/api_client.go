package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}
type APIClient struct {
	Config                    Config
	HTTP                      HTTPDoer
	APITimeout, UploadTimeout time.Duration
}
type APIError struct {
	Cause      error
	Status     int
	Retryable  bool
	RetryAfter time.Duration
}

func (e *APIError) Unwrap() error { return e.Cause }
func (e *APIError) Error() string { return fmt.Sprintf("petición Titvo falló (HTTP %d)", e.Status) }
func (c *APIClient) doer() HTTPDoer {
	var base *http.Client
	if c.HTTP == nil {
		base = &http.Client{}
	} else if v, ok := c.HTTP.(*http.Client); ok {
		base = v
	} else {
		return c.HTTP
	}
	clone := *base
	clone.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirección no permitida") }
	return &clone
}
func safeHTTPS(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}
func (c *APIClient) request(ctx context.Context, method, endpoint string, body io.Reader, auth bool, size int64) ([]byte, error) {
	if !safeHTTPS(endpoint) {
		return nil, fmt.Errorf("endpoint HTTPS no válido")
	}
	d := c.APITimeout
	if d <= 0 {
		d = 60 * time.Second
	}
	if !auth {
		d = c.UploadTimeout
		if d <= 0 {
			d = 5 * time.Minute
		}
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("petición no válida")
	}
	if auth {
		req.Header.Set("X-API-Key", c.Config.APIKeyHeader())
		req.Header.Set("Content-Type", "application/json")
	} else {
		req.Header.Set("Content-Type", "application/x-tar+gzip")
		req.ContentLength = size
	}
	resp, err := c.doer().Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if parent.Err() != nil {
			return nil, parent.Err()
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &APIError{Retryable: true, Cause: context.DeadlineExceeded}
		}
		return nil, &APIError{Retryable: true}
	}
	if resp == nil || resp.Body == nil {
		return nil, fmt.Errorf("respuesta HTTP vacía")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		delay := time.Duration(0)
		if n, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && n > 0 {
			delay = time.Duration(n) * time.Second
		} else if date, e := http.ParseTime(resp.Header.Get("Retry-After")); e == nil {
			delay = time.Until(date)
			if delay < 0 {
				delay = 0
			}
		}
		return nil, &APIError{Status: resp.StatusCode, Retryable: resp.StatusCode == 429 || resp.StatusCode >= 500, RetryAfter: delay}
	}
	const maxResponse = 16 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("lectura de respuesta falló")
	}
	if len(data) > maxResponse {
		return nil, fmt.Errorf("respuesta demasiado grande")
	}
	return data, nil
}
func (c *APIClient) post(ctx context.Context, path string, payload any, dest any) error {
	u, err := url.Parse(c.Config.APIEndpoint)
	if err != nil || !safeHTTPS(c.Config.APIEndpoint) || u.RawQuery != "" {
		return fmt.Errorf("endpoint HTTPS no válido")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("petición JSON no válida")
	}
	data, err := c.request(ctx, http.MethodPost, strings.TrimRight(c.Config.APIEndpoint, "/")+path, bytes.NewReader(body), true, 0)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("respuesta JSON no válida")
	}
	return nil
}
func (c *APIClient) Presign(ctx context.Context, batchID, name string, originals []string) (string, error) {
	payload := map[string]any{"source": "cli", "args": map[string]any{"batch_id": batchID, "files": []map[string]string{{"name": name, "content_type": "application/x-tar+gzip"}}, "original_files": originals}}
	var r struct {
		URLs map[string]string `json:"presigned_urls"`
	}
	if err := c.post(ctx, "/cli-files", payload, &r); err != nil {
		return "", err
	}
	u := r.URLs[name]
	if !safeHTTPS(u) {
		return "", fmt.Errorf("URL de subida no válida")
	}
	return u, nil
}
func (c *APIClient) Upload(ctx context.Context, u, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("no se pudo abrir el snapshot")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	_, err = c.request(ctx, http.MethodPut, u, f, false, info.Size())
	return err
}
func (c *APIClient) Start(ctx context.Context, input RunScanInput) (string, error) {
	var r RunScanOutput
	err := c.post(ctx, "/run-scan", map[string]any{"source": "cli", "args": map[string]string{"batch_id": input.BatchId, "repository_url": sanitizeRepositoryURL(input.RepositoryURL), "branch": input.Branch}}, &r)
	if err != nil {
		return "", err
	}
	if !validScanID(r.ScanID) {
		return "", fmt.Errorf("scan_id no válido")
	}
	return r.ScanID, nil
}
func (c *APIClient) Status(ctx context.Context, id string) (GetScanStatusOutput, error) {
	var r GetScanStatusOutput
	if !validScanID(id) {
		return r, fmt.Errorf("scan_id no válido")
	}
	err := c.post(ctx, "/scan-status", map[string]string{"scan_id": id}, &r)
	return r, err
}
