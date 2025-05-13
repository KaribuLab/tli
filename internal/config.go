package internal

import (
	"encoding/json"
	"os"
)

type Config struct {
	UserID      string `json:"user_id"`
	APIKey      string `json:"api_key"`
	APIEndpoint string `json:"api_endpoint"`
}

func NewConfig(userId string, apiKey string, apiEndpoint string) *Config {
	return &Config{UserID: userId, APIKey: apiKey, APIEndpoint: apiEndpoint}
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
	return json.Unmarshal(data, c)
}
