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
	"time"
)

type blockingReader struct {
	started chan<- struct{}
	release <-chan struct{}
	sent    bool
}

func (r *blockingReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		close(r.started)
		<-r.release
		p[0] = 'x'
		return 1, io.EOF
	}
	return 0, io.EOF
}

func TestLocalStagedCommitWaitsForActiveWriter(t *testing.T) {
	p, err := NewLocalProvider(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalProvider failed: %v", err)
	}
	ctx := context.Background()
	staged, err := p.CreateStaged(ctx, "UPLOAD_WAIT_123", "OBJECT_WAIT_123", 1, 1)
	if err != nil {
		t.Fatalf("CreateStaged failed: %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := staged.WriteChunk(ctx, 0, 0, &blockingReader{started: started, release: release}, 1)
		writeDone <- writeErr
	}()
	<-started

	commitDone := make(chan error, 1)
	go func() {
		commitDone <- staged.Commit(ctx, "OBJECT_WAIT_123", 1)
	}()
	select {
	case err := <-commitDone:
		t.Fatalf("commit completed while writer was active: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	if err := <-writeDone; err != nil {
		t.Fatalf("WriteChunk failed: %v", err)
	}
	if err := <-commitDone; err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
}

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

	// Open and verify io.ReadSeekCloser supports seeking
	rsc, err := p.Open(ctx, key)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if _, err := rsc.Seek(13, io.SeekStart); err != nil {
		rsc.Close()
		t.Fatalf("Seek failed: %v", err)
	}
	tail, err := io.ReadAll(rsc)
	rsc.Close()
	if err != nil {
		t.Fatalf("io.ReadAll after Seek failed: %v", err)
	}
	if string(tail) != "file contents" {
		t.Fatalf("Seek+Read content mismatch: got %q, want %q", tail, "file contents")
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

func TestLocalProvider_StagedChunkUploadAndCommit(t *testing.T) {
	base := t.TempDir()
	p, err := NewLocalProvider(base)
	if err != nil {
		t.Fatalf("NewLocalProvider failed: %v", err)
	}

	ctx := context.Background()
	uploadID := "UP1234567890"
	storageKey := "KEY1234567890"

	chunk0 := []byte("chunk-zero-payload-data-")
	chunk1 := []byte("chunk-one-payload-data--")
	chunk2 := []byte("chunk-two-payload-final!")
	totalSize := int64(len(chunk0) + len(chunk1) + len(chunk2))
	chunkSize := int64(len(chunk0))

	staged, err := p.CreateStaged(ctx, uploadID, storageKey, totalSize, chunkSize)
	if err != nil {
		t.Fatalf("CreateStaged failed: %v", err)
	}

	// Write chunks out of order: chunk 1, then chunk 0, then chunk 2
	n1, err := staged.WriteChunk(ctx, 1, chunkSize, bytes.NewReader(chunk1), chunkSize)
	if err != nil || n1 != int64(len(chunk1)) {
		t.Fatalf("WriteChunk(1) failed: n=%d err=%v", n1, err)
	}

	n0, err := staged.WriteChunk(ctx, 0, 0, bytes.NewReader(chunk0), chunkSize)
	if err != nil || n0 != int64(len(chunk0)) {
		t.Fatalf("WriteChunk(0) failed: n=%d err=%v", n0, err)
	}

	n2, err := staged.WriteChunk(ctx, 2, chunkSize*2, bytes.NewReader(chunk2), chunkSize)
	if err != nil || n2 != int64(len(chunk2)) {
		t.Fatalf("WriteChunk(2) failed: n=%d err=%v", n2, err)
	}

	// Commit staged upload
	if err := staged.Commit(ctx, storageKey, totalSize); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Verify temp file is gone
	tempPath := filepath.Join(base, ".tmp_upload_"+uploadID)
	if _, err := os.Stat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected temp file %q to be gone after Commit, got err=%v", tempPath, err)
	}

	// Verify committed file
	rc, err := p.Get(ctx, storageKey)
	if err != nil {
		t.Fatalf("Get on committed key failed: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	expected := append(append(chunk0, chunk1...), chunk2...)
	if !bytes.Equal(data, expected) {
		t.Fatalf("committed content mismatch: got %q, want %q", string(data), string(expected))
	}

	// Verify abort cleans up
	abortUploadID := "UP_ABORT_123"
	abortStaged, err := p.CreateStaged(ctx, abortUploadID, "KEY_ABORT", 100, 50)
	if err != nil {
		t.Fatalf("CreateStaged abort failed: %v", err)
	}
	abortTempPath := filepath.Join(base, ".tmp_upload_"+abortUploadID)
	if _, err := os.Stat(abortTempPath); err != nil {
		t.Fatalf("expected temp file to exist: %v", err)
	}
	if err := abortStaged.Abort(ctx); err != nil {
		t.Fatalf("Abort failed: %v", err)
	}
	if _, err := os.Stat(abortTempPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected temp file to be removed after Abort, got %v", err)
	}
}
