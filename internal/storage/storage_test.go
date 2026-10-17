package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalProvider_SaveGetDelete(t *testing.T) {
	base := t.TempDir()
	p, err := NewLocalProvider(base)
	if err != nil {
		t.Fatalf("NewLocalProvider failed: %v", err)
	}

	ctx := context.Background()
	key := "OBJECT1234567890"
	payload := []byte("confidential file contents")

	if err := p.Save(ctx, key, bytes.NewReader(payload)); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Verify file permissions are not world-readable
	info, err := os.Stat(filepath.Join(base, key))
	if err != nil {
		t.Fatalf("os.Stat failed: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o007 != 0 {
		t.Errorf("expected stored file not to be world-accessible, got mode %04o", mode)
	}

	// Overwrite with O_EXCL must be rejected
	if err := p.Save(ctx, key, strings.NewReader("overwrite attempt")); err == nil {
		t.Fatalf("expected second Save on same key to fail due to O_EXCL, got nil")
	}

	// Get and verify content unchanged
	rc, err := p.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil {
		t.Fatalf("io.ReadAll failed: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Get content mismatch: got %q, want %q", got, payload)
	}

	// Delete and verify removal
	if err := p.Delete(ctx, key); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := p.Get(ctx, key); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist after Delete, got %v", err)
	}
	// Deleting a non-existent key is idempotent
	if err := p.Delete(ctx, key); err != nil {
		t.Fatalf("expected Delete on missing key to succeed, got %v", err)
	}
}

func TestLocalProvider_RejectsPathTraversalAndSymlinks(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "uploads")
	outsideTarget := filepath.Join(parent, "config.json")
	if err := os.WriteFile(outsideTarget, []byte(`{"secret":"keep"}`), 0o600); err != nil {
		t.Fatalf("failed to create outside target: %v", err)
	}

	p, err := NewLocalProvider(base)
	if err != nil {
		t.Fatalf("NewLocalProvider failed: %v", err)
	}

	ctx := context.Background()
	maliciousKeys := []string{
		"",
		".",
		"..",
		"../config.json",
		"/../../config.json",
		"..\\config.json",
		"sub/file.txt",
		"sub\\file.txt",
		"a/../../config.json",
		"bad\x00key",
		"/etc/passwd",
	}

	for _, key := range maliciousKeys {
		if err := p.Save(ctx, key, strings.NewReader("pwned")); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Save(%q): expected ErrInvalidKey, got %v", key, err)
		}
		if _, err := p.Get(ctx, key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Get(%q): expected ErrInvalidKey, got %v", key, err)
		}
		if err := p.Delete(ctx, key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Delete(%q): expected ErrInvalidKey, got %v", key, err)
		}
	}

	// Symlink escape inside basePath must be rejected by os.Root
	symlinkPath := filepath.Join(base, "escape_link")
	if err := os.Symlink(outsideTarget, symlinkPath); err == nil {
		if _, err := p.Get(ctx, "escape_link"); err == nil {
			t.Errorf("expected Get on symlink escaping root to fail, but it succeeded")
		}
		if err := p.Save(ctx, "escape_link", strings.NewReader("pwned")); err == nil {
			t.Errorf("expected Save on symlink escaping root to fail, but it succeeded")
		}
	}

	// Ensure outside file was never modified or deleted
	after, err := os.ReadFile(outsideTarget)
	if err != nil {
		t.Fatalf("outside target was deleted or unreadable: %v", err)
	}
	if string(after) != `{"secret":"keep"}` {
		t.Fatalf("outside target was modified: %q", string(after))
	}
}
