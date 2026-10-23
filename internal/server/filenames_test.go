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

func TestIsValidLogoMagicBytes_SVGSecurity(t *testing.T) {
	validSVG := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><circle cx="50" cy="50" r="40"/></svg>`)
	if !isValidLogoMagicBytes(".svg", validSVG) {
		t.Fatalf("expected valid SVG to pass")
	}

	// SVG with script in first 4KB
	scriptSVG := []byte(`<svg><script>alert(1)</script></svg>`)
	if isValidLogoMagicBytes(".svg", scriptSVG) {
		t.Fatalf("expected SVG with <script> to be rejected")
	}

	// SVG with script after 4KB padding (bypass of 4KB limit)
	padding := make([]byte, 5000)
	for i := range padding {
		padding[i] = ' '
	}
	bypassSVG := append([]byte(`<svg>`), padding...)
	bypassSVG = append(bypassSVG, []byte(`<script>alert(1)</script></svg>`)...)
	if isValidLogoMagicBytes(".svg", bypassSVG) {
		t.Fatalf("expected SVG with script after 4KB padding to be rejected")
	}

	// SVG with animation onload handler
	animSVG := []byte(`<svg><animate onbegin="alert(1)"/></svg>`)
	if isValidLogoMagicBytes(".svg", animSVG) {
		t.Fatalf("expected SVG with animate onbegin to be rejected")
	}

	// SVG with foreignObject
	foreignSVG := []byte(`<svg><foreignObject><body><iframe src="evil.com"></iframe></body></foreignObject></svg>`)
	if isValidLogoMagicBytes(".svg", foreignSVG) {
		t.Fatalf("expected SVG with foreignObject to be rejected")
	}
}
