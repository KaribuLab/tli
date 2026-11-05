package internal

import "testing"

func TestConfigFromEnv(t *testing.T) {
	t.Run("returns nil when any variable is missing", func(t *testing.T) {
		t.Setenv("TLI_USER_ID", "user")
		t.Setenv("TLI_API_KEY", "")
		t.Setenv("TLI_API_ENDPOINT", "https://api.example.com")
		if got := configFromEnv(); got != nil {
			t.Fatalf("expected nil, got %+v", got)
		}
	})

	t.Run("builds config when all variables are set", func(t *testing.T) {
		t.Setenv("TLI_USER_ID", "user")
		t.Setenv("TLI_API_KEY", "key")
		t.Setenv("TLI_API_ENDPOINT", "https://api.example.com")
		got := configFromEnv()
		if got == nil {
			t.Fatal("expected config, got nil")
		}
		if got.UserID != "user" || got.APIKey != "key" || got.APIEndpoint != "https://api.example.com" {
			t.Fatalf("unexpected config: %+v", got)
		}
	})
}

func TestGetAPIConfigFallsBackToEnv(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no ~/.tli/config.json here
	t.Setenv("TLI_USER_ID", "user")
	t.Setenv("TLI_API_KEY", "key")
	t.Setenv("TLI_API_ENDPOINT", "https://api.example.com")
	cfg, err := getAPIConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.UserID != "user" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}
