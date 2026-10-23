package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Default(t *testing.T) {
	tmpPath := filepath.Join(t.TempDir(), "config.json")
	cfg, err := Load(tmpPath, false)
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
	// Verify auto-generated config has random secrets and correct 0600 file mode
	if !IsValidJWTKey(cfg.JWTKey) {
		t.Errorf("expected auto-generated JWT key, got %q", cfg.JWTKey)
	}
	if cfg.DataKey == "" {
		t.Errorf("expected auto-generated DataKey, got empty")
	}
	info, statErr := os.Stat(tmpPath)
	if statErr != nil {
		t.Fatalf("expected generated config file to exist: %v", statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected 0600 permissions, got %04o", perm)
	}
}

func TestLoadConfig_EnvOnly(t *testing.T) {
	tmpPath := filepath.Join(t.TempDir(), "should_not_exist.json")
	t.Setenv("FL_JWT_KEY", "0123456789abcdef0123456789abcdef-valid-secret")
	t.Setenv("FL_DATA_KEY", "0123456789abcdef0123456789abcdef-valid-data-key")

	cfg, err := Load(tmpPath, true)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("expected file %s not to be created in EnvOnly mode", tmpPath)
	}
	if cfg.JWTKey != "0123456789abcdef0123456789abcdef-valid-secret" {
		t.Errorf("expected JWTKey from env, got %s", cfg.JWTKey)
	}
	if cfg.DataKey != "0123456789abcdef0123456789abcdef-valid-data-key" {
		t.Errorf("expected DataKey from env, got %s", cfg.DataKey)
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

func TestEnsureDataKey_GeneratesAndPersists(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")

	cfg := DefaultConfig()
	if cfg.DataKey != "" {
		t.Fatalf("expected DefaultConfig().DataKey to be empty, got %q", cfg.DataKey)
	}

	if err := cfg.EnsureDataKey(cfgPath); err != nil {
		t.Fatalf("EnsureDataKey failed: %v", err)
	}
	if cfg.DataKey == "" {
		t.Fatalf("expected DataKey to be generated")
	}

	// Verify persistence
	loaded, err := Load(cfgPath, false)
	if err != nil {
		t.Fatalf("failed to load saved config: %v", err)
	}
	if loaded.DataKey != cfg.DataKey {
		t.Errorf("expected loaded DataKey %q to equal saved DataKey %q", loaded.DataKey, cfg.DataKey)
	}
}

func TestEnsureDrives_UnifiedPool(t *testing.T) {
	// 1. Empty drives initializes from legacy fields
	cfg := DefaultConfig()
	cfg.StorageType = "s3"
	cfg.S3Endpoint = "s3.wasabisys.com"
	cfg.S3Protocol = "http"
	cfg.S3SkipSSLVerify = true
	cfg.Drives = nil
	cfg.EnsureDrives()

	if len(cfg.Drives) != 1 {
		t.Fatalf("expected 1 drive in pool, got %d", len(cfg.Drives))
	}
	d := cfg.Drives[0]
	if !d.IsDefault || cfg.DefaultDriveID != d.ID {
		t.Errorf("expected default drive flag set, got is_default=%v, default_drive_id=%s", d.IsDefault, cfg.DefaultDriveID)
	}
	if d.Type != "s3" || d.S3Protocol != "http" || !d.S3SkipSSLVerify {
		t.Errorf("expected drive to inherit s3 settings, got type=%s, proto=%s, skipSSL=%v", d.Type, d.S3Protocol, d.S3SkipSSLVerify)
	}

	// 2. Multiple drives with primary selection
	cfg2 := DefaultConfig()
	cfg2.Drives = []Drive{
		{ID: "d1", Name: "Local 1", Type: "local", Enabled: true, LocalStoragePath: "/path1"},
		{ID: "d2", Name: "Local 2", Type: "local", Enabled: true, LocalStoragePath: "/path2"},
	}
	cfg2.DefaultDriveID = "d2"
	cfg2.EnsureDrives()

	if cfg2.Drives[0].IsDefault {
		t.Errorf("d1 should not be default")
	}
	if !cfg2.Drives[1].IsDefault {
		t.Errorf("d2 should be default")
	}
	if cfg2.LocalStoragePath != "/path2" {
		t.Errorf("expected legacy LocalStoragePath to be synced to /path2, got %s", cfg2.LocalStoragePath)
	}
}

func TestPostgresTLS_ConfigDefaultsAndOverrides(t *testing.T) {
	// Default is false
	def := DefaultConfig()
	if def.PostgresTLS {
		t.Errorf("expected default PostgresTLS to be false, got true")
	}
	if def.DBTLS {
		t.Errorf("expected default DBTLS to be false, got true")
	}

	// File with postgres_tls: true
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(cfgFile, []byte(`{"db_type": "postgres", "postgres_tls": true}`), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg, err := Load(cfgFile, false)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	if !cfg.PostgresTLS || !cfg.DBTLS {
		t.Errorf("expected PostgresTLS and DBTLS to be true from file")
	}

	// File with db_tls: true (synced to PostgresTLS)
	cfgFile2 := filepath.Join(tmpDir, "config2.json")
	if err := os.WriteFile(cfgFile2, []byte(`{"db_type": "postgres", "db_tls": true}`), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	cfg2, err := Load(cfgFile2, false)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	if !cfg2.PostgresTLS || !cfg2.DBTLS {
		t.Errorf("expected PostgresTLS and DBTLS to be true from db_tls")
	}

	// Env override
	t.Setenv("FL_POSTGRES_TLS", "true")
	cfgEnv, err := Load("", true)
	if err != nil {
		t.Fatalf("failed to load env config: %v", err)
	}
	if !cfgEnv.PostgresTLS {
		t.Errorf("expected PostgresTLS true from FL_POSTGRES_TLS")
	}
}
