package internal

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

type RunScanInput struct{ BatchId, RepositoryURL, Branch string }
type RunScanOutput struct {
	ScanID string `json:"scan_id"`
}
type GetScanStatusOutput struct {
	Status string       `json:"status"`
	Result StatusResult `json:"result"`
}

var ErrCredentials = errors.New("faltan credenciales: usa tli setup o TLI_API_KEY/TLI_API_ENDPOINT")

func getAPIConfig() (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("no se pudo localizar configuración")
	}
	c := &Config{}
	if err = c.Load(filepath.Join(home, ".tli", "config.json")); err != nil {
		if env := configFromEnv(); env != nil {
			return env, nil
		}
		return nil, ErrCredentials
	}
	return c, nil
}
func configFromEnv() *Config {
	key, endpoint := os.Getenv("TLI_API_KEY"), os.Getenv("TLI_API_ENDPOINT")
	if key == "" || endpoint == "" {
		return nil
	}
	return &Config{APIKey: key, APIEndpoint: endpoint}
}
func sanitizeRepositoryURL(raw string) string {
	clean := strings.TrimSpace(raw)
	if strings.ContainsAny(clean, "\r\n\x00") {
		return ""
	}
	if !strings.Contains(clean, "://") {
		return strings.SplitN(strings.SplitN(clean, "?", 2)[0], "#", 2)[0]
	}
	parsed, err := url.Parse(clean)
	if err != nil || parsed.Host == "" {
		return ""
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.ForceQuery = false
	return parsed.String()
}
