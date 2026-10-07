package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Default(t *testing.T) {
	cfg, err := Load("non_existent_config.json")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.DBType != "sqlite" {
		t.Errorf("expected default DBType 'sqlite', got %s", cfg.DBType)
	}
}

func TestLoadConfig_File(t *testing.T) {
	content := []byte(`{"db_type": "postgres", "port": 9000, "ssl": true}`)
	tmpFile := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(tmpFile, content, 0644); err != nil {
		t.Fatalf("failed to create temp config: %v", err)
	}
	cfg, err := Load(tmpFile)
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
	defer func() {
		os.Unsetenv("FL_DB_TYPE")
		os.Unsetenv("FL_PORT")
	}()
	cfg, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if cfg.DBType != "" {
		t.Errorf("expected default DBType '', got %s", cfg.DBType)
	}
	if cfg.Port != 8000 {
		t.Errorf("expected 8000, got %d", cfg.Port)
	}
}