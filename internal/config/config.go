package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// Config holds the fileline configuration
type Config struct {
	DBType           string `json:"db_type"`
	SQLiteURL        string `json:"sqlite_url"`
	PostgresURL      string `json:"postgres_url"`
	Port             int    `json:"port"`
	SSL              bool   `json:"ssl"`
	SSLCertPath      string `json:"ssl_cert_path"`
	SSLKeyPath       string `json:"ssl_key_path"`
	ReverseProxy     bool   `json:"reverse_proxy"`
	JWTKey           string `json:"jwt_key"`
	StorageType      string `json:"storage_type"` // "local" or "s3"
	LocalStoragePath string `json:"local_storage_path"`
	S3Endpoint       string `json:"s3_endpoint"`
	S3Region         string `json:"s3_region"`
	S3Bucket         string `json:"s3_bucket"`
	S3AccessKey      string `json:"s3_access_key"`
	S3SecretKey      string `json:"s3_secret_key"`
	S3UseSSL         bool   `json:"s3_use_ssl"`
	MaxUploadSizeMB  int    `json:"max_upload_size_mb"`
	ChunkThresholdMB int    `json:"chunk_threshold_mb"`
	ChunkSizeMB      int    `json:"chunk_size_mb"`
	Domain           string `json:"domain"` // e.g. "localhost:8080" or "fileline.example.com"
	EnvOnly          bool   `json:"-"`      // Not serialized
}

// DefaultConfig returns a Config with default values
func DefaultConfig() Config {
	return Config{
		Port:             8080,
		SSL:              false,
		ReverseProxy:     false,
		JWTKey:           "default-secret-key-change-me",
		StorageType:      "local",
		LocalStoragePath: "./uploads",
		Domain:           "localhost",
		MaxUploadSizeMB:  1024,
		ChunkThresholdMB: 50,
		ChunkSizeMB:      10,
	}
}

// Load reads config. If envOnly is true, it only uses environment variables
func Load(configPath string, envOnly bool) (*Config, error) {
	cfg := DefaultConfig()
	// Try reading config.json
	file, err := os.ReadFile(configPath)
	if err == nil {
		if err := json.Unmarshal(file, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
		return &cfg, nil
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
	if v, ok := os.LookupEnv("FL_STORAGE_TYPE"); ok {
		cfg.StorageType = v
	}
	if v, ok := os.LookupEnv("FL_LOCAL_STORAGE_PATH"); ok {
		cfg.LocalStoragePath = v
	}
	if v, ok := os.LookupEnv("FL_S3_ENDPOINT"); ok {
		cfg.S3Endpoint = v
	}
	if v, ok := os.LookupEnv("FL_S3_REGION"); ok {
		cfg.S3Region = v
	}
	if v, ok := os.LookupEnv("FL_S3_BUCKET"); ok {
		cfg.S3Bucket = v
	}
	if v, ok := os.LookupEnv("FL_S3_ACCESS_KEY"); ok {
		cfg.S3AccessKey = v
	}
	if v, ok := os.LookupEnv("FL_S3_SECRET_KEY"); ok {
		cfg.S3SecretKey = v
	}
	if v, ok := os.LookupEnv("FL_S3_USE_SSL"); ok {
		if ssl, err := strconv.ParseBool(v); err == nil {
			cfg.S3UseSSL = ssl
		}
	}
	if v, ok := os.LookupEnv("FL_DOMAIN"); ok {
		cfg.Domain = v
	}
	if v, ok := os.LookupEnv("FL_MAX_UPLOAD_SIZE_MB"); ok {
		if limit, err := strconv.Atoi(v); err == nil {
			cfg.MaxUploadSizeMB = limit
		}
	}
	if v, ok := os.LookupEnv("FL_CHUNK_THRESHOLD_MB"); ok {
		if threshold, err := strconv.Atoi(v); err == nil {
			cfg.ChunkThresholdMB = threshold
		}
	}
	if v, ok := os.LookupEnv("FL_CHUNK_SIZE_MB"); ok {
		if size, err := strconv.Atoi(v); err == nil {
			cfg.ChunkSizeMB = size
		}
	}
	return &cfg, nil
}

// Save writes the current configuration back to config.json.
func (c *Config) Save(configPath string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(configPath, data, 0644)
}
