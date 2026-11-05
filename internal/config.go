package internal

import (
	"encoding/json"
	"os"
	"strings"
)

// encryptedPrefix marks an API key that the server encrypted during
// `tli setup`. The server decrypts it before validating.
const encryptedPrefix = "ENC:"

type Config struct {
	UserID      string `json:"user_id"`
	APIKey      string `json:"api_key"`
	APIEndpoint string `json:"api_endpoint"`

	// encrypted is true when APIKey is the server-encrypted value stored by
	// `tli setup` (~/.tli/config.json). Raw keys (e.g. from env vars in CI)
	// are sent as-is; the server hashes and validates them directly.
	encrypted bool
}

func NewConfig(userId string, apiKey string, apiEndpoint string) *Config {
	return &Config{UserID: userId, APIKey: apiKey, APIEndpoint: apiEndpoint, encrypted: true}
}

// APIKeyHeader returns the value to send in the X-API-Key header: the
// encrypted key with the ENC: prefix, or the raw key untouched.
func (c *Config) APIKeyHeader() string {
	if strings.HasPrefix(c.APIKey, encryptedPrefix) {
		return c.APIKey
	}
	if c.encrypted {
		return encryptedPrefix + c.APIKey
	}
	return c.APIKey
}

func (c *Config) Save(filepath string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath, data, 0600)
}

func (c *Config) Load(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, c); err != nil {
		return err
	}
	// The config file only ever holds the key encrypted by `tli setup`.
	c.encrypted = true
	return nil
}
