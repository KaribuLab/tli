package internal

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigFromEnv(t *testing.T) {
	t.Run("returns nil when api key or endpoint is missing", func(t *testing.T) {
		t.Setenv("TLI_API_KEY", "")
		t.Setenv("TLI_API_ENDPOINT", "https://api.example.com")
		if got := configFromEnv(); got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
	})

	t.Run("builds config from api key and endpoint only", func(t *testing.T) {
		t.Setenv("TLI_API_KEY", "tvok-raw")
		t.Setenv("TLI_API_ENDPOINT", "https://api.example.com")
		got := configFromEnv()
		if got == nil || got.APIKey != "tvok-raw" || got.APIEndpoint != "https://api.example.com" {
			t.Fatalf("unexpected config: %+v", got)
		}
	})

	t.Run("raw key from env is sent without ENC prefix", func(t *testing.T) {
		t.Setenv("TLI_API_KEY", "tvok-raw")
		t.Setenv("TLI_API_ENDPOINT", "https://api.example.com")
		if got := configFromEnv().APIKeyHeader(); got != "tvok-raw" {
			t.Fatalf("header = %q, want raw key", got)
		}
	})

	t.Run("env value already prefixed with ENC is kept", func(t *testing.T) {
		t.Setenv("TLI_API_KEY", "ENC:abc")
		t.Setenv("TLI_API_ENDPOINT", "https://api.example.com")
		if got := configFromEnv().APIKeyHeader(); got != "ENC:abc" {
			t.Fatalf("header = %q, want ENC:abc", got)
		}
	})
}

func TestConfigFileKeyIsSentEncrypted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := NewConfig("user", "srv-cipher", "https://api.example.com").Save(path); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{}
	if err := cfg.Load(path); err != nil {
		t.Fatal(err)
	}
	if got := cfg.APIKeyHeader(); got != "ENC:srv-cipher" {
		t.Fatalf("header = %q, want ENC: prefix", got)
	}
	// The flag must not leak into the file.
	data, _ := os.ReadFile(path)
	if string(data) == "" || strings.Contains(string(data), "encrypted") {
		t.Fatalf("unexpected file content: %s", data)
	}
}

func TestGetAPIConfigFallsBackToEnv(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no ~/.tli/config.json here
	t.Setenv("TLI_API_KEY", "tvok-raw")
	t.Setenv("TLI_API_ENDPOINT", "https://api.example.com")
	cfg, err := getAPIConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIKeyHeader() != "tvok-raw" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}
