package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Default(t *testing.T) {
	cfg, err := Load("non_existent_config.json", false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.DBType != "" {
		t.Errorf("expected default DBType '', got %s", cfg.DBType)
	}
	if !cfg.BlockIndexing {
		t.Errorf("expected default BlockIndexing true, got false")
	}
	if !cfg.GzipEnabled {
		t.Errorf("expected default GzipEnabled true, got false")
	}
	if !cfg.MinifyResponses {
		t.Errorf("expected default MinifyResponses true, got false")
	}
}

func TestLoadConfig_File(t *testing.T) {
	content := []byte(`{"db_type": "postgres", "port": 9000, "ssl": true, "block_indexing": false}`)
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	cfg, err := Load(tmpFile, false)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.DBType != "postgres" {
		t.Errorf("expected 'postgres', got %s", cfg.DBType)
	}
	if cfg.Port != 9000 {
		t.Errorf("expected 9000, got %d", cfg.Port)
	}
	if !cfg.SSL {
		t.Errorf("expected SSL true, got false")
	}
	if cfg.BlockIndexing {
		t.Errorf("expected BlockIndexing false from file, got true")
	}
}

func TestLoadConfig_EnvOverride(t *testing.T) {
	// Setup file with postgres
	content := []byte(`{"db_type": "postgres", "port": 9000}`)
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	// Override with env
	os.Setenv("FL_DB_TYPE", "sqlite")
	os.Setenv("FL_PORT", "8000")
	os.Setenv("FL_BLOCK_INDEXING", "false")
	os.Setenv("FL_GZIP_ENABLED", "false")
	os.Setenv("FL_MINIFY_RESPONSES", "false")
	defer func() {
		os.Unsetenv("FL_DB_TYPE")
		os.Unsetenv("FL_PORT")
		os.Unsetenv("FL_BLOCK_INDEXING")
		os.Unsetenv("FL_GZIP_ENABLED")
		os.Unsetenv("FL_MINIFY_RESPONSES")
	}()
	cfg, err := Load("", true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.DBType != "sqlite" {
		t.Errorf("expected 'sqlite', got %s", cfg.DBType)
	}
	if cfg.Port != 8000 {
		t.Errorf("expected 8000, got %d", cfg.Port)
	}
	if cfg.BlockIndexing {
		t.Errorf("expected BlockIndexing false from env override, got true")
	}
	if cfg.GzipEnabled {
		t.Errorf("expected GzipEnabled false from env override, got true")
	}
	if cfg.MinifyResponses {
		t.Errorf("expected MinifyResponses false from env override, got true")
	}
}

func TestEnsureJWTKey_GeneratesAndPersists0600(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")

	// 1. DefaultConfig starts with empty JWTKey
	cfg := DefaultConfig()
	if cfg.JWTKey != "" {
		t.Fatalf("expected DefaultConfig().JWTKey to be empty, got %q", cfg.JWTKey)
	}

	if err := cfg.EnsureJWTKey(cfgPath); err != nil {
		t.Fatalf("EnsureJWTKey failed: %v", err)
	}
	if !IsValidJWTKey(cfg.JWTKey) {
		t.Fatalf("expected generated JWTKey to be valid (>= %d bytes), got %q (len=%d)", MinJWTKeyLength, cfg.JWTKey, len(cfg.JWTKey))
	}

	// Verify file was written with 0600 permissions
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("expected config.json to be written: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected config.json permissions 0600, got %04o", perm)
	}

	// 2. Short key (< 32 bytes) is rejected and rotated
	firstKey := cfg.JWTKey
	cfg.JWTKey = "too-short-secret"
	if IsValidJWTKey(cfg.JWTKey) {
		t.Fatalf("expected short key to be rejected by IsValidJWTKey")
	}
	if err := cfg.EnsureJWTKey(cfgPath); err != nil {
		t.Fatalf("EnsureJWTKey on short key failed: %v", err)
	}
	if cfg.JWTKey == "too-short-secret" || cfg.JWTKey == firstKey || !IsValidJWTKey(cfg.JWTKey) {
		t.Fatalf("expected short key to be replaced with a new random key, got %q", cfg.JWTKey)
	}

	// 3. Existing valid key is preserved across restarts
	savedKey := cfg.JWTKey
	loaded, err := Load(cfgPath, false)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if err := loaded.EnsureJWTKey(cfgPath); err != nil {
		t.Fatalf("EnsureJWTKey on loaded config failed: %v", err)
	}
	if loaded.JWTKey != savedKey {
		t.Errorf("expected existing valid key to be preserved: got %q, want %q", loaded.JWTKey, savedKey)
	}
}

func TestEnsureJWTKey_EnvOnlyRefusesWeakKey(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"whitespace_only", "   "},
		{"too_short", "short-key-under-32-bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.EnvOnly = true
			cfg.JWTKey = tc.key
			if err := cfg.EnsureJWTKey(""); err == nil {
				t.Errorf("expected EnsureJWTKey in EnvOnly mode to reject key %q, got nil", tc.key)
			}
		})
	}

	// Valid 32+ byte key in EnvOnly mode succeeds
	cfg := DefaultConfig()
	cfg.EnvOnly = true
	cfg.JWTKey = "0123456789abcdef0123456789abcdef-valid-secret"
	if err := cfg.EnsureJWTKey(""); err != nil {
		t.Errorf("expected valid FL_JWT_KEY in EnvOnly mode to succeed, got %v", err)
	}
}
