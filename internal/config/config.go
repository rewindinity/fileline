package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// Config holds the fileline configuration
type Config struct {
	DBType       string `json:"db_type"`
	SQLiteURL    string `json:"sqlite_url"`
	PostgresURL  string `json:"postgres_url"`
	Port         int    `json:"port"`
	SSL          bool   `json:"ssl"`
	SSLCertPath  string `json:"ssl_cert_path"`
	SSLKeyPath   string `json:"ssl_key_path"`
	ReverseProxy bool   `json:"reverse_proxy"`
	JWTKey       string `json:"jwt_key"`
}

// DefaultConfig returns a Config with default values
func DefaultConfig() Config {
	return Config{
		DBType:       "sqlite",
		SQLiteURL:    "fileline.db",
		Port:         8080,
		SSL:          false,
		ReverseProxy: false,
		JWTKey:       "default-secret-key-change-me",
	}
}

// Load reads config from config.json
func Load(configPath string) (*Config, error) {
	cfg := DefaultConfig()
	// Try reading config.json
	file, err := os.ReadFile(configPath)
	if err == nil {
		if err := json.Unmarshal(file, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	// Override with environment variables
	if v, ok := os.LookupEnv("FL_DB_TYPE"); ok {
		cfg.DBType = v
	}
	if v, ok := os.LookupEnv("FL_SQLITE_URL"); ok {
		cfg.SQLiteURL = v
	}
	if v, ok := os.LookupEnv("FL_POSTGRES_URL"); ok {
		cfg.PostgresURL = v
	}
	if v, ok := os.LookupEnv("FL_PORT"); ok {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.Port = port
		}
	}
	if v, ok := os.LookupEnv("FL_SSL"); ok {
		if ssl, err := strconv.ParseBool(v); err == nil {
			cfg.SSL = ssl
		}
	}
	if v, ok := os.LookupEnv("FL_SSL_CERT_PATH"); ok {
		cfg.SSLCertPath = v
	}
	if v, ok := os.LookupEnv("FL_SSL_KEY_PATH"); ok {
		cfg.SSLKeyPath = v
	}
	if v, ok := os.LookupEnv("FL_REVERSE_PROXY"); ok {
		if proxy, err := strconv.ParseBool(v); err == nil {
			cfg.ReverseProxy = proxy
		}
	}
	if v, ok := os.LookupEnv("FL_JWT_KEY"); ok {
		cfg.JWTKey = v
	}
	return &cfg, nil
}