package server

import (
	"crypto/rand"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxFileNameBytes bounds the length of user-supplied file names (common filesystem limit)
const maxFileNameBytes = 255

var errInvalidFileName = errors.New("invalid file name")

// sanitizeFileName turns a client-supplied file name into a safe display name.
func sanitizeFileName(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", errInvalidFileName
	}
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)

	if name == "" || name == "." || name == ".." || name == "/" || len(name) > maxFileNameBytes {
		return "", errInvalidFileName
	}
	return name, nil
}

// newStorageKey returns a random, path-safe key for storing an uploaded object
func newStorageKey() string {
	return rand.Text()
}

// newUploadID returns a random, unguessable, path-safe chunked upload session ID
func newUploadID() string {
	return rand.Text()
}

// isValidUploadID verifies that id is a single, safe path component
func isValidUploadID(id string) bool {
	if id == "" || id == "." || id == ".." || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// chunkBaseDir is the directory that holds per-upload chunk directories
func chunkBaseDir() string {
	if dir := os.Getenv("FL_CHUNKS_DIR"); dir != "" {
		return dir
	}
	return filepath.Join(os.TempDir(), "fileline_chunks")
}

// openChunkBaseRoot ensures the chunk base directory exists and opens it as an os.Root
func openChunkBaseRoot() (*os.Root, error) {
	base := chunkBaseDir()
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, err
	}
	return os.OpenRoot(base)
}

// openChunkUploadRoot opens the per-upload temporary directory confined inside chunkBaseDir() via os.Root
func openChunkUploadRoot(uploadID string) (*os.Root, error) {
	if !isValidUploadID(uploadID) {
		return nil, errInvalidFileName
	}
	baseRoot, err := openChunkBaseRoot()
	if err != nil {
		return nil, err
	}
	defer baseRoot.Close()
	return baseRoot.OpenRoot(uploadID)
}

// removeChunkUploadDir safely removes a per-upload temporary directory confined under chunkBaseDir() via os.Root
func removeChunkUploadDir(uploadID string) error {
	if !isValidUploadID(uploadID) {
		return errInvalidFileName
	}
	baseRoot, err := openChunkBaseRoot()
	if err != nil {
		return err
	}
	defer baseRoot.Close()
	return baseRoot.RemoveAll(uploadID)
}
