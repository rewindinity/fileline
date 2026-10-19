package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MinJWTKeyLength is the minimum accepted length (in bytes) of a session signing key
const MinJWTKeyLength = 32

type Drive struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"` // "local" or "s3"
	Enabled          bool   `json:"enabled"`
	LocalStoragePath string `json:"local_storage_path"`
	S3Endpoint       string `json:"s3_endpoint"`
	S3Region         string `json:"s3_region"`
	S3Bucket         string `json:"s3_bucket"`
	S3AccessKey      string `json:"s3_access_key"`
	S3SecretKey      string `json:"s3_secret_key"`
	S3UseSSL         bool   `json:"s3_use_ssl"`
}

// Config holds the fileline configuration
type Config struct {
	DBType         string   `json:"db_type"`
	SQLiteURL      string   `json:"sqlite_url"`
	PostgresURL    string   `json:"postgres_url"`
	Port           int      `json:"port"`
	SSL            bool     `json:"ssl"`
	SSLCertPath    string   `json:"ssl_cert_path"`
	SSLKeyPath     string   `json:"ssl_key_path"`
	ReverseProxy   bool     `json:"reverse_proxy"`
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	JWTKey         string   `json:"jwt_key"`
	// Legacy fields
	StorageType      string  `json:"storage_type"` // "local" or "s3"
	LocalStoragePath string  `json:"local_storage_path"`
	S3Endpoint       string  `json:"s3_endpoint"`
	S3Region         string  `json:"s3_region"`
	S3Bucket         string  `json:"s3_bucket"`
	S3AccessKey      string  `json:"s3_access_key"`
	S3SecretKey      string  `json:"s3_secret_key"`
	S3UseSSL         bool    `json:"s3_use_ssl"`
	Drives           []Drive `json:"drives"`
	MaxUploadSizeMB  int     `json:"max_upload_size_mb"`
	ChunkThresholdMB int     `json:"chunk_threshold_mb"`
	ChunkSizeMB      int     `json:"chunk_size_mb"`
	ChunksDir        string  `json:"chunks_dir,omitempty"`
	Domain           string  `json:"domain"` // e.g. "localhost:8080" or "fileline.example.com"
	Theme            string  `json:"theme"`
	Accent           string  `json:"accent"`
	CustomAccentHex  string  `json:"custom_accent_hex"`
	CustomLogo       string  `json:"custom_logo"`
	DefaultLanguage  string  `json:"default_language"`
	BlockIndexing    bool    `json:"block_indexing"`
	Debug            bool    `json:"debug"`
	GzipEnabled      bool    `json:"gzip_enabled"`
	MinifyResponses  bool    `json:"minify_responses"`
	EnvOnly          bool    `json:"-"` // Not serialized
}

// DefaultConfig returns a Config with default values
func DefaultConfig() Config {
	return Config{
		Port:             8080,
		SSL:              false,
		ReverseProxy:     false,
		JWTKey:           "", // never hard-coded; see EnsureJWTKey
		StorageType:      "local",
		LocalStoragePath: "./uploads",
		Domain:           "localhost",
		MaxUploadSizeMB:  1024,
		ChunkThresholdMB: 50,
		ChunkSizeMB:      10,
		Theme:            "dark-blue",
		Accent:           "blue",
		CustomAccentHex:  "#2563eb",
		CustomLogo:       "/static/logo.svg",
		DefaultLanguage:  "en",
		BlockIndexing:    true,
		GzipEnabled:      true,
		MinifyResponses:  true,
	}
}

// Load reads config from configPath (unless envOnly is true), then applies FL_* environment variable overrides.
func Load(configPath string, envOnly bool) (*Config, error) {
	cfg := DefaultConfig()
	cfg.EnvOnly = envOnly
	if !envOnly && configPath != "" {
		file, err := os.ReadFile(configPath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		} else {
			if err := json.Unmarshal(file, &cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
			cfg.EnvOnly = envOnly
		}
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
	if v, ok := os.LookupEnv("FL_TRUSTED_PROXIES"); ok {
		var proxies []string
		for _, p := range strings.Split(v, ",") {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				proxies = append(proxies, trimmed)
			}
		}
		cfg.TrustedProxies = proxies
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
	if v, ok := os.LookupEnv("FL_CHUNKS_DIR"); ok {
		cfg.ChunksDir = v
	}
	if v, ok := os.LookupEnv("FL_THEME"); ok {
		cfg.Theme = v
	}
	if v, ok := os.LookupEnv("FL_ACCENT"); ok {
		cfg.Accent = v
	}
	if v, ok := os.LookupEnv("FL_CUSTOM_ACCENT_HEX"); ok {
		cfg.CustomAccentHex = v
	}
	if v, ok := os.LookupEnv("FL_CUSTOM_LOGO"); ok {
		cfg.CustomLogo = v
	}
	if v, ok := os.LookupEnv("FL_BLOCK_INDEXING"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.BlockIndexing = b
		}
	}
	if v, ok := os.LookupEnv("FL_DEBUG"); ok {
		if d, err := strconv.ParseBool(v); err == nil {
			cfg.Debug = d
		}
	}
	if v, ok := os.LookupEnv("FL_GZIP_ENABLED"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.GzipEnabled = b
		}
	} else if v, ok := os.LookupEnv("FL_GZIP_COMPRESSION"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.GzipEnabled = b
		}
	}
	if v, ok := os.LookupEnv("FL_MINIFY_RESPONSES"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.MinifyResponses = b
		}
	} else if v, ok := os.LookupEnv("FL_MINIFY_ENABLED"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.MinifyResponses = b
		}
	}
	return &cfg, nil
}

// IsValidJWTKey reports whether key meets the minimum length requirement
func IsValidJWTKey(key string) bool {
	k := strings.TrimSpace(key)
	return len(k) >= MinJWTKeyLength
}

// GenerateJWTKey generates a new cryptographically random 256-bit (32-byte) key, base64url-encoded
func GenerateJWTKey() (string, error) {
	b := make([]byte, MinJWTKeyLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random JWT key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c *Config) EnsureJWTKey(configPath string) error {
	if IsValidJWTKey(c.JWTKey) {
		return nil
	}
	if c.EnvOnly {
		return fmt.Errorf("FL_JWT_KEY must be set to at least %d random bytes", MinJWTKeyLength)
	}
	key, err := GenerateJWTKey()
	if err != nil {
		return err
	}
	c.JWTKey = key
	if configPath != "" {
		return c.Save(configPath)
	}
	return nil
}

// Save writes the current configuration atomically to configPath with mode 0600
func (c *Config) Save(configPath string) error {
	if c.EnvOnly || configPath == "" {
		return nil
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	dir := filepath.Dir(configPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("failed to create config directory: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp config file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("failed to set config file permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("failed to write config file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("failed to sync config file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to close config file: %w", err)
	}
	if err := os.Rename(tmpName, configPath); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("failed to replace config file: %w", err)
	}
	return nil
}

// DriveView is a sanitized representation of Drive safe for rendering into HTML/JS templates
type DriveView struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Enabled          bool   `json:"enabled"`
	LocalStoragePath string `json:"local_storage_path"`
	S3Endpoint       string `json:"s3_endpoint"`
	S3Region         string `json:"s3_region"`
	S3Bucket         string `json:"s3_bucket"`
	S3AccessKey      string `json:"s3_access_key"`
	S3SecretSet      bool   `json:"s3_secret_set"`
	S3UseSSL         bool   `json:"s3_use_ssl"`
}

// ConfigView is a dedicated template view-model containing only non-secret configuration fields
type ConfigView struct {
	DBType           string      `json:"db_type"`
	SQLiteURL        string      `json:"sqlite_url"`
	Port             int         `json:"port"`
	SSL              bool        `json:"ssl"`
	ReverseProxy     bool        `json:"reverse_proxy"`
	StorageType      string      `json:"storage_type"`
	LocalStoragePath string      `json:"local_storage_path"`
	S3Endpoint       string      `json:"s3_endpoint"`
	S3Region         string      `json:"s3_region"`
	S3Bucket         string      `json:"s3_bucket"`
	S3AccessKey      string      `json:"s3_access_key"`
	S3SecretSet      bool        `json:"s3_secret_set"`
	S3UseSSL         bool        `json:"s3_use_ssl"`
	Drives           []DriveView `json:"drives"`
	MaxUploadSizeMB  int         `json:"max_upload_size_mb"`
	ChunkThresholdMB int         `json:"chunk_threshold_mb"`
	ChunkSizeMB      int         `json:"chunk_size_mb"`
	Domain           string      `json:"domain"`
	Theme            string      `json:"theme"`
	Accent           string      `json:"accent"`
	CustomAccentHex  string      `json:"custom_accent_hex"`
	CustomLogo       string      `json:"custom_logo"`
	DefaultLanguage  string      `json:"default_language"`
	BlockIndexing    bool        `json:"block_indexing"`
	Debug            bool        `json:"debug"`
	GzipEnabled      bool        `json:"gzip_enabled"`
	MinifyResponses  bool        `json:"minify_responses"`
	EnvOnly          bool        `json:"-"`
}

// SanitizedDrives returns a slice of DriveView with S3SecretKey stripped and S3SecretSet populated
func (c *Config) SanitizedDrives() []DriveView {
	if c == nil || len(c.Drives) == 0 {
		return []DriveView{}
	}
	views := make([]DriveView, len(c.Drives))
	for i, d := range c.Drives {
		views[i] = DriveView{
			ID:               d.ID,
			Name:             d.Name,
			Type:             d.Type,
			Enabled:          d.Enabled,
			LocalStoragePath: d.LocalStoragePath,
			S3Endpoint:       d.S3Endpoint,
			S3Region:         d.S3Region,
			S3Bucket:         d.S3Bucket,
			S3AccessKey:      d.S3AccessKey,
			S3SecretSet:      d.S3SecretKey != "",
			S3UseSSL:         d.S3UseSSL,
		}
	}
	return views
}

// SanitizedView returns a ConfigView stripped of all secrets (JWTKey, S3SecretKey, PostgresURL, and drive secrets)
func (c *Config) SanitizedView() ConfigView {
	if c == nil {
		return ConfigView{}
	}
	return ConfigView{
		DBType:           c.DBType,
		SQLiteURL:        c.SQLiteURL,
		Port:             c.Port,
		SSL:              c.SSL,
		ReverseProxy:     c.ReverseProxy,
		StorageType:      c.StorageType,
		LocalStoragePath: c.LocalStoragePath,
		S3Endpoint:       c.S3Endpoint,
		S3Region:         c.S3Region,
		S3Bucket:         c.S3Bucket,
		S3AccessKey:      c.S3AccessKey,
		S3SecretSet:      c.S3SecretKey != "",
		S3UseSSL:         c.S3UseSSL,
		Drives:           c.SanitizedDrives(),
		MaxUploadSizeMB:  c.MaxUploadSizeMB,
		ChunkThresholdMB: c.ChunkThresholdMB,
		ChunkSizeMB:      c.ChunkSizeMB,
		Domain:           c.Domain,
		Theme:            c.Theme,
		Accent:           c.Accent,
		CustomAccentHex:  c.CustomAccentHex,
		CustomLogo:       c.CustomLogo,
		DefaultLanguage:  c.DefaultLanguage,
		BlockIndexing:    c.BlockIndexing,
		Debug:            c.Debug,
		GzipEnabled:      c.GzipEnabled,
		MinifyResponses:  c.MinifyResponses,
		EnvOnly:          c.EnvOnly,
	}
}
