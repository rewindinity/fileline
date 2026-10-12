package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"fileline/internal/db"
)

// ChunkUpload holds metadata and progress of a chunked file upload
type ChunkUpload struct {
	ID           string
	OriginalName string
	CustomName   string
	URLPath      string
	TotalSize    int64
	TotalChunks  int
	IsPrivate    bool
	DriveID      string
	UserID       int
	Received     []bool
	TempDir      string
	CreatedAt    time.Time
}

func (s *Server) uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseMultipartForm(10 << 20) // 10 MB limit
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	s.mu.RLock()
	maxSize := s.cfg.MaxUploadSizeMB * 1024 * 1024
	s.mu.RUnlock()
	if maxSize > 0 && header.Size > int64(maxSize) {
		http.Error(w, "File exceeds maximum allowed size", http.StatusBadRequest)
		return
	}

	originalName := header.Filename
	customName := r.FormValue("custom_name")
	urlPath := r.FormValue("url_path")
	if urlPath == "" {
		if customName != "" {
			urlPath = customName
		} else {
			urlPath = originalName
		}
	}

	isPrivate := r.FormValue("is_private") == "on"
	driveID := r.FormValue("drive_id")

	s.mu.RLock()
	st := s.getProvider(driveID)
	storageType := driveID
	if storageType == "" || storageType == "default" {
		storageType = s.cfg.StorageType
	}
	database := s.db
	s.mu.RUnlock()

	username := r.Context().Value("username").(string)
	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.StorageQuotaMB > 0 {
		total, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
		if total+header.Size > int64(user.StorageQuotaMB)*1024*1024 {
			http.Error(w, "Storage quota exceeded", http.StatusForbidden)
			return
		}
	}

	// Generate a unique storage key
	storageKey := fmt.Sprintf("%d-%s", time.Now().UnixNano(), originalName)

	if err := st.Save(r.Context(), storageKey, file); err != nil {
		http.Error(w, "Failed to save file to storage: "+err.Error(), http.StatusInternalServerError)
		return
	}

	f := &db.File{
		OriginalName: originalName,
		CustomName:   customName,
		URLPath:      urlPath,
		Size:         header.Size,
		IsPrivate:    isPrivate,
		StorageType:  storageType,
		StoragePath:  storageKey,
		UserID:       user.ID,
	}

	if err := db.InsertFile(r.Context(), database, f); err != nil {
		st.Delete(r.Context(), storageKey) // Rollback
		http.Error(w, "Failed to save file metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) chunkUploadInitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		FileName    string `json:"file_name"`
		TotalSize   int64  `json:"total_size"`
		TotalChunks int    `json:"total_chunks"`
		IsPrivate   bool   `json:"is_private"`
		CustomName  string `json:"custom_name"`
		URLPath     string `json:"url_path"`
		DriveID     string `json:"drive_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	maxSize := s.cfg.MaxUploadSizeMB * 1024 * 1024
	s.mu.RUnlock()
	if maxSize > 0 && req.TotalSize > int64(maxSize) {
		http.Error(w, "File exceeds maximum allowed size", http.StatusBadRequest)
		return
	}
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.StorageQuotaMB > 0 {
		total, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
		if total+req.TotalSize > int64(user.StorageQuotaMB)*1024*1024 {
			http.Error(w, "Storage quota exceeded", http.StatusForbidden)
			return
		}
	}
	uploadID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), req.FileName)
	tempDir := filepath.Join(os.TempDir(), "fileline_chunks", uploadID)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		http.Error(w, "Failed to create temp directory", http.StatusInternalServerError)
		return
	}

	upload := &ChunkUpload{
		ID:           uploadID,
		OriginalName: req.FileName,
		CustomName:   req.CustomName,
		URLPath:      req.URLPath,
		TotalSize:    req.TotalSize,
		TotalChunks:  req.TotalChunks,
		IsPrivate:    req.IsPrivate,
		DriveID:      req.DriveID,
		UserID:       user.ID,
		Received:     make([]bool, req.TotalChunks),
		TempDir:      tempDir,
		CreatedAt:    time.Now(),
	}
	s.chunkMu.Lock()
	s.chunkUploads[uploadID] = upload
	s.chunkMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"upload_id": uploadID,
	})
}

func (s *Server) chunkUploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseMultipartForm(32 << 20) // 32MB max memory for parsing
	uploadID := r.FormValue("upload_id")
	chunkIndex, err := strconv.Atoi(r.FormValue("chunk_index"))
	if err != nil {
		http.Error(w, "Invalid chunk index", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("chunk")
	if err != nil {
		http.Error(w, "Failed to read chunk", http.StatusBadRequest)
		return
	}
	defer file.Close()
	s.chunkMu.RLock()
	upload, ok := s.chunkUploads[uploadID]
	s.chunkMu.RUnlock()
	if !ok {
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}
	if chunkIndex < 0 || chunkIndex >= upload.TotalChunks {
		http.Error(w, "Chunk index out of bounds", http.StatusBadRequest)
		return
	}
	chunkPath := filepath.Join(upload.TempDir, fmt.Sprintf("%d", chunkIndex))
	dst, err := os.Create(chunkPath)
	if err != nil {
		http.Error(w, "Failed to save chunk to disk", http.StatusInternalServerError)
		return
	}
	io.Copy(dst, file)
	dst.Close()
	s.chunkMu.Lock()
	upload.Received[chunkIndex] = true
	s.chunkMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) chunkUploadCompleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		UploadID string `json:"upload_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	s.chunkMu.RLock()
	upload, ok := s.chunkUploads[req.UploadID]
	s.chunkMu.RUnlock()
	if !ok {
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}
	for i, received := range upload.Received {
		if !received {
			http.Error(w, fmt.Sprintf("Missing chunk %d", i), http.StatusBadRequest)
			return
		}
	}
	// Assemble file
	assembledPath := filepath.Join(upload.TempDir, "assembled")
	finalFile, err := os.Create(assembledPath)
	if err != nil {
		http.Error(w, "Failed to create assembled file", http.StatusInternalServerError)
		return
	}
	var actualSize int64
	for i := 0; i < upload.TotalChunks; i++ {
		chunkPath := filepath.Join(upload.TempDir, fmt.Sprintf("%d", i))
		chunkData, err := os.ReadFile(chunkPath)
		if err != nil {
			finalFile.Close()
			http.Error(w, "Failed to read chunk from disk", http.StatusInternalServerError)
			return
		}
		n, err := finalFile.Write(chunkData)
		if err != nil {
			finalFile.Close()
			http.Error(w, "Failed to write assembled file", http.StatusInternalServerError)
			return
		}
		actualSize += int64(n)
	}
	finalFile.Close()
	// Clean up temp dir and session after we are done storing
	defer func() {
		os.RemoveAll(upload.TempDir)
		s.chunkMu.Lock()
		delete(s.chunkUploads, upload.ID)
		s.chunkMu.Unlock()
	}()
	// Re-open for storage provider
	assembledFile, err := os.Open(assembledPath)
	if err != nil {
		http.Error(w, "Failed to open assembled file", http.StatusInternalServerError)
		return
	}
	defer assembledFile.Close()
	urlPath := upload.URLPath
	if urlPath == "" {
		if upload.CustomName != "" {
			urlPath = upload.CustomName
		} else {
			urlPath = upload.OriginalName
		}
	}
	s.mu.RLock()
	st := s.getProvider(upload.DriveID)
	storageType := upload.DriveID
	if storageType == "" || storageType == "default" {
		storageType = s.cfg.StorageType
	}
	database := s.db
	s.mu.RUnlock()
	storageKey := fmt.Sprintf("%d-%s", time.Now().UnixNano(), upload.OriginalName)
	if err := st.Save(r.Context(), storageKey, assembledFile); err != nil {
		http.Error(w, "Failed to save file to storage: "+err.Error(), http.StatusInternalServerError)
		return
	}
	f := &db.File{
		OriginalName: upload.OriginalName,
		CustomName:   upload.CustomName,
		URLPath:      urlPath,
		Size:         actualSize,
		IsPrivate:    upload.IsPrivate,
		StorageType:  storageType,
		StoragePath:  storageKey,
		UserID:       upload.UserID,
	}
	if err := db.InsertFile(r.Context(), database, f); err != nil {
		st.Delete(r.Context(), storageKey) // Rollback
		http.Error(w, "Failed to save file metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
