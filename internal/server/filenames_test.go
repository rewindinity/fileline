package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChunkBaseDir_Defaults(t *testing.T) {
	origEnv := os.Getenv("FL_CHUNKS_DIR")
	origTmp := os.Getenv("TMPDIR")
	defer func() {
		os.Setenv("FL_CHUNKS_DIR", origEnv)
		os.Setenv("TMPDIR", origTmp)
	}()

	os.Unsetenv("FL_CHUNKS_DIR")
	os.Unsetenv("TMPDIR")

	expected := filepath.Join(os.TempDir(), "fileline_chunks")
	if got := chunkBaseDir(); got != expected {
		t.Fatalf("expected chunkBaseDir() to be %q, got %q", expected, got)
	}
}

func TestChunkBaseDir_FLChunksDirOverride(t *testing.T) {
	origEnv := os.Getenv("FL_CHUNKS_DIR")
	defer os.Setenv("FL_CHUNKS_DIR", origEnv)

	customDir := "/custom/chunks/path"
	os.Setenv("FL_CHUNKS_DIR", customDir)

	if got := chunkBaseDir(); got != customDir {
		t.Fatalf("expected chunkBaseDir() to use FL_CHUNKS_DIR (%q), got %q", customDir, got)
	}
}

func TestChunkBaseDir_TMPDIROverride(t *testing.T) {
	origEnv := os.Getenv("FL_CHUNKS_DIR")
	origTmp := os.Getenv("TMPDIR")
	defer func() {
		os.Setenv("FL_CHUNKS_DIR", origEnv)
		os.Setenv("TMPDIR", origTmp)
	}()

	os.Unsetenv("FL_CHUNKS_DIR")
	customTmp := t.TempDir()
	os.Setenv("TMPDIR", customTmp)

	expected := filepath.Join(customTmp, "fileline_chunks")
	if got := chunkBaseDir(); got != expected {
		t.Fatalf("expected chunkBaseDir() to use TMPDIR base %q, got %q", expected, got)
	}
}
