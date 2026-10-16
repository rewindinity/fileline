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
	defer func() {
		os.Unsetenv("FL_DB_TYPE")
		os.Unsetenv("FL_PORT")
		os.Unsetenv("FL_BLOCK_INDEXING")
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
}

