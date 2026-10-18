package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fileline/internal/db"
	"fileline/internal/logger"
)

const (
	maxTotalChunks              = 10000
	maxConcurrentUploadsPerUser = 5
	chunkUploadTTL              = time.Hour
	defaultChunkSizeMB          = 10
	defaultMaxBodyBytes         = 1 << 20  // 1 MB default limit for non-upload routes
	maxJSONOrFormBodyBytes      = 64 << 10 // 64 KB limit for small JSON/form routes
	maxLogoUploadBytes          = 1 << 20  // 1 MB limit for custom logo uploads
)

// ChunkUpload holds metadata and progress of a chunked file upload
type ChunkUpload struct {
	mu            sync.Mutex
	ID            string
	OriginalName  string
	CustomName    string
	URLPath       string
	TotalSize     int64
	TotalChunks   int
	ChunkSize     int64
	IsPrivate     bool
	StatsEnabled  bool
	DriveID       string
	UserID        int
	Received      []bool
	ChunkSizes    []int64
	BytesReceived int64
	Completing    bool
	TempDir       string
	CreatedAt     time.Time
}

func (s *Server) configuredChunkSizeBytes() int64 {
	s.mu.RLock()
	mb := defaultChunkSizeMB
	if s.cfg != nil && s.cfg.ChunkSizeMB > 0 {
		mb = s.cfg.ChunkSizeMB
	}
	s.mu.RUnlock()
	return int64(mb) << 20
}

type countingReader struct {
	r io.Reader
	n int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

func isMaxBytesError(err error) bool {
	var maxBytesErr *http.MaxBytesError
	return errors.As(err, &maxBytesErr)
}

func (s *Server) uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	s.mu.RLock()
	maxSize := int64(s.cfg.MaxUploadSizeMB) * 1024 * 1024
	maxUploadMB := s.cfg.MaxUploadSizeMB
	s.mu.RUnlock()
	if maxSize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxSize+(1<<20))
	}

	if err := r.ParseMultipartForm(8 << 20); err != nil {
		if isMaxBytesError(err) {
			http.Error(w, "File exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "File exceeds maximum allowed size or invalid form", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	username := r.Context().Value("username").(string)

	if maxSize > 0 && header.Size > maxSize {
		logger.Action("User '%s' upload rejected: file '%s' (%s) exceeds maximum allowed size (%d MB)", username, header.Filename, logger.FormatBytes(header.Size), maxUploadMB)
		http.Error(w, "File exceeds maximum allowed size", http.StatusBadRequest)
		return
	}

	originalName, err := sanitizeFileName(header.Filename)
	if err != nil {
		http.Error(w, "Invalid file name", http.StatusBadRequest)
		return
	}
	customName := strings.TrimSpace(r.FormValue("custom_name"))
	if len(customName) > maxCustomNameLen {
		http.Error(w, "Custom name too long", http.StatusBadRequest)
		return
	}
	urlPath := strings.TrimSpace(r.FormValue("url_path"))
	explicitURLPath := urlPath != ""
	if explicitURLPath {
		if err := validateURLPath(urlPath); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else {
		if customName != "" {
			urlPath = slugifyURLPath(customName)
		} else {
			urlPath = slugifyURLPath(originalName)
		}
	}

	isPrivate := r.FormValue("is_private") == "on"
	statsEnabled := r.FormValue("stats_enabled") == "on"
	driveID := strings.TrimSpace(r.FormValue("drive_id"))
	if !s.validateDriveID(driveID) {
		http.Error(w, "Invalid storage drive", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	st := s.getProvider(driveID)
	storageType := driveID
	if storageType == "" || storageType == "default" {
		storageType = s.cfg.StorageType
	}
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var currentUsed int64
	if user.StorageQuotaMB > 0 {
		currentUsed, _ = db.GetUserTotalStorage(r.Context(), database, user.ID)
		if currentUsed+header.Size > int64(user.StorageQuotaMB)*1024*1024 {
			logger.Action("User '%s' upload rejected: quota exceeded for file '%s' (%s)", username, originalName, logger.FormatBytes(header.Size))
			http.Error(w, "Storage quota exceeded", http.StatusForbidden)
			return
		}
	}

	// Storage key is random and never derived from the client-supplied name
	storageKey := newStorageKey()

	var reader io.Reader = file
	if maxSize > 0 {
		reader = io.LimitReader(file, maxSize+1)
	}
	cr := &countingReader{r: reader}
	if err := st.Save(r.Context(), storageKey, cr); err != nil {
		s.internalError(w, r, "Failed to save file to storage", err)
		return
	}
	actualSize := cr.n
	if maxSize > 0 && actualSize > maxSize {
		_ = st.Delete(r.Context(), storageKey)
		http.Error(w, "File exceeds maximum allowed size", http.StatusBadRequest)
		return
	}
	if user.StorageQuotaMB > 0 && currentUsed+actualSize > int64(user.StorageQuotaMB)*1024*1024 {
		_ = st.Delete(r.Context(), storageKey)
		http.Error(w, "Storage quota exceeded", http.StatusForbidden)
		return
	}

	f := &db.File{
		OriginalName: originalName,
		CustomName:   customName,
		URLPath:      urlPath,
		Size:         actualSize,
		IsPrivate:    isPrivate,
		StatsEnabled: statsEnabled,
		StorageType:  storageType,
		StoragePath:  storageKey,
		UserID:       user.ID,
	}

	if err := db.InsertFile(r.Context(), database, f); err != nil {
		if isUniqueConstraintError(err) {
			if !explicitURLPath {
				f.URLPath = appendRandomURLPathSuffix(urlPath)
				if retryErr := db.InsertFile(r.Context(), database, f); retryErr == nil {
					logger.Action("User '%s' uploaded file '%s' (size: %s, storage: %s, path: %s, private: %t)", username, originalName, logger.FormatBytes(actualSize), storageType, storageKey, isPrivate)
					http.Redirect(w, r, "/", http.StatusFound)
					return
				}
			}
			_ = st.Delete(r.Context(), storageKey)
			http.Error(w, "URL path already in use", http.StatusConflict)
			return
		}
		st.Delete(r.Context(), storageKey) // Rollback
		s.internalError(w, r, "Failed to save file metadata to database", err)
		return
	}

	logger.Action("User '%s' uploaded file '%s' (size: %s, storage: %s, path: %s, private: %t)", username, originalName, logger.FormatBytes(actualSize), storageType, storageKey, isPrivate)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) chunkUploadInitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
	var req struct {
		FileName     string `json:"file_name"`
		TotalSize    int64  `json:"total_size"`
		TotalChunks  int    `json:"total_chunks"`
		IsPrivate    bool   `json:"is_private"`
		StatsEnabled bool   `json:"stats_enabled"`
		CustomName   string `json:"custom_name"`
		URLPath      string `json:"url_path"`
		DriveID      string `json:"drive_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if isMaxBytesError(err) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	// The client-supplied name is metadata only
	fileName, err := sanitizeFileName(req.FileName)
	if err != nil {
		http.Error(w, "Invalid file name", http.StatusBadRequest)
		return
	}
	req.FileName = fileName
	req.CustomName = strings.TrimSpace(req.CustomName)
	if len(req.CustomName) > maxCustomNameLen {
		http.Error(w, "Custom name too long", http.StatusBadRequest)
		return
	}
	req.URLPath = strings.TrimSpace(req.URLPath)
	if req.URLPath != "" {
		if err := validateURLPath(req.URLPath); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.mu.RLock()
		initDB := s.db
		s.mu.RUnlock()
		if existing, err := db.GetFileByURL(r.Context(), initDB, req.URLPath); err == nil && existing != nil {
			http.Error(w, "URL path already in use", http.StatusConflict)
			return
		}
	}
	req.DriveID = strings.TrimSpace(req.DriveID)
	if !s.validateDriveID(req.DriveID) {
		http.Error(w, "Invalid storage drive", http.StatusBadRequest)
		return
	}

	if req.TotalSize <= 0 {
		http.Error(w, "Invalid total size", http.StatusBadRequest)
		return
	}
	if req.TotalChunks <= 0 || req.TotalChunks > maxTotalChunks {
		http.Error(w, "Invalid total chunks", http.StatusBadRequest)
		return
	}

	chunkSize := s.configuredChunkSizeBytes()
	expectedChunks := int((req.TotalSize + chunkSize - 1) / chunkSize)
	if expectedChunks < 1 {
		expectedChunks = 1
	}
	if req.TotalChunks != expectedChunks {
		http.Error(w, "Total chunks does not match total size and configured chunk size", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	maxSize := int64(s.cfg.MaxUploadSizeMB) * 1024 * 1024
	maxUploadMB := s.cfg.MaxUploadSizeMB
	database := s.db
	s.mu.RUnlock()

	username, _ := r.Context().Value("username").(string)
	if maxSize > 0 && req.TotalSize > maxSize {
		logger.Action("User '%s' chunked upload init rejected: file '%s' exceeds maximum allowed size (%d MB)", username, req.FileName, maxUploadMB)
		http.Error(w, "File exceeds maximum allowed size", http.StatusBadRequest)
		return
	}

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.StorageQuotaMB > 0 {
		total, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
		if total+req.TotalSize > int64(user.StorageQuotaMB)*1024*1024 {
			logger.Action("User '%s' chunked upload init rejected: quota exceeded for file '%s' (%s)", username, req.FileName, logger.FormatBytes(req.TotalSize))
			http.Error(w, "Storage quota exceeded", http.StatusForbidden)
			return
		}
	}

	now := time.Now()
	s.cleanupExpiredUploads(now)

	s.chunkMu.Lock()
	activeForUser := 0
	for _, u := range s.chunkUploads {
		if u.UserID == user.ID {
			activeForUser++
		}
	}
	if activeForUser >= maxConcurrentUploadsPerUser {
		s.chunkMu.Unlock()
		http.Error(w, "Too many concurrent upload sessions", http.StatusTooManyRequests)
		return
	}

	// Random, server-generated ID: the temp directory is always a direct child of chunkBaseDir(), confined via os.Root.
	uploadID := newUploadID()
	baseDir := chunkBaseDir()
	tempDir := filepath.Join(baseDir, uploadID)
	baseRoot, err := openChunkBaseRoot()
	if err != nil {
		s.chunkMu.Unlock()
		s.internalError(w, r, "Failed to open chunk base directory", err)
		return
	}
	if err := baseRoot.Mkdir(uploadID, 0o700); err != nil {
		baseRoot.Close()
		s.chunkMu.Unlock()
		s.internalError(w, r, "Failed to create temp directory", err)
		return
	}
	baseRoot.Close()

	upload := &ChunkUpload{
		ID:           uploadID,
		OriginalName: req.FileName,
		CustomName:   req.CustomName,
		URLPath:      req.URLPath,
		TotalSize:    req.TotalSize,
		TotalChunks:  req.TotalChunks,
		ChunkSize:    chunkSize,
		IsPrivate:    req.IsPrivate,
		StatsEnabled: req.StatsEnabled,
		DriveID:      req.DriveID,
		UserID:       user.ID,
		Received:     make([]bool, req.TotalChunks),
		ChunkSizes:   make([]int64, req.TotalChunks),
		TempDir:      tempDir,
		CreatedAt:    now,
	}
	s.chunkUploads[uploadID] = upload
	s.chunkMu.Unlock()

	logger.Action("User '%s' initiated chunked upload for '%s' (size: %s, chunks: %d, upload_id: %s)", username, req.FileName, logger.FormatBytes(req.TotalSize), req.TotalChunks, uploadID)
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
	username, _ := r.Context().Value("username").(string)
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	currentUser, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	maxChunkBytes := s.configuredChunkSizeBytes()
	r.Body = http.MaxBytesReader(w, r.Body, maxChunkBytes+(1<<20))
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		if isMaxBytesError(err) {
			http.Error(w, "Chunk exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Chunk exceeds maximum allowed size or invalid form", http.StatusBadRequest)
		return
	}
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

	if !ok || upload.UserID != currentUser.ID {
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}

	if chunkIndex < 0 || chunkIndex >= upload.TotalChunks {
		http.Error(w, "Chunk index out of bounds", http.StatusBadRequest)
		return
	}

	chunkLimit := upload.ChunkSize
	if chunkLimit <= 0 {
		chunkLimit = maxChunkBytes
	}

	upload.mu.Lock()
	defer upload.mu.Unlock()
	if upload.Completing {
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}

	uploadRoot, err := openChunkUploadRoot(upload.ID)
	if err != nil {
		s.internalError(w, r, "Failed to open chunk directory", err)
		return
	}
	defer uploadRoot.Close()

	chunkName := strconv.Itoa(chunkIndex)
	dst, err := uploadRoot.OpenFile(chunkName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		s.internalError(w, r, "Failed to save chunk to disk", err)
		return
	}
	written, copyErr := io.Copy(dst, io.LimitReader(file, chunkLimit+1))
	closeErr := dst.Close()
	if copyErr != nil {
		_ = uploadRoot.Remove(chunkName)
		if isMaxBytesError(copyErr) {
			http.Error(w, "Chunk exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
			return
		}
		s.internalError(w, r, "Failed to write chunk to disk", copyErr)
		return
	}
	if closeErr != nil {
		_ = uploadRoot.Remove(chunkName)
		s.internalError(w, r, "Failed to close chunk file", closeErr)
		return
	}
	if written > chunkLimit {
		_ = uploadRoot.Remove(chunkName)
		http.Error(w, "Chunk exceeds maximum configured chunk size", http.StatusBadRequest)
		return
	}

	prevSize := upload.ChunkSizes[chunkIndex]
	newTotalReceived := upload.BytesReceived - prevSize + written
	if newTotalReceived > upload.TotalSize {
		_ = uploadRoot.Remove(chunkName)
		upload.Received[chunkIndex] = false
		upload.ChunkSizes[chunkIndex] = 0
		upload.BytesReceived -= prevSize
		http.Error(w, "Uploaded chunks exceed declared total size", http.StatusBadRequest)
		return
	}

	upload.Received[chunkIndex] = true
	upload.ChunkSizes[chunkIndex] = written
	upload.BytesReceived = newTotalReceived

	logger.Debug("Received chunk %d/%d for upload_id %s", chunkIndex+1, upload.TotalChunks, uploadID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) chunkUploadCompleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username, _ := r.Context().Value("username").(string)
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	currentUser, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
	var req struct {
		UploadID string `json:"upload_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if isMaxBytesError(err) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	s.chunkMu.Lock()
	upload, ok := s.chunkUploads[req.UploadID]
	if !ok || upload.UserID != currentUser.ID {
		s.chunkMu.Unlock()
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}
	upload.mu.Lock()
	if upload.Completing {
		upload.mu.Unlock()
		s.chunkMu.Unlock()
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}
	for i, received := range upload.Received {
		if !received {
			upload.mu.Unlock()
			s.chunkMu.Unlock()
			http.Error(w, fmt.Sprintf("Missing chunk %d", i), http.StatusBadRequest)
			return
		}
	}

	upload.Completing = true
	delete(s.chunkUploads, req.UploadID)
	upload.mu.Unlock()
	s.chunkMu.Unlock()

	uploadRoot, err := openChunkUploadRoot(upload.ID)
	if err != nil {
		_ = removeChunkUploadDir(upload.ID)
		s.internalError(w, r, "Failed to open chunk upload directory", err)
		return
	}
	// Clean up temp dir after we are done storing (confined to chunkBaseDir via os.Root)
	defer func() {
		uploadRoot.Close()
		_ = removeChunkUploadDir(upload.ID)
	}()

	s.mu.RLock()
	st := s.getProvider(upload.DriveID)
	storageType := upload.DriveID
	if storageType == "" || storageType == "default" {
		storageType = s.cfg.StorageType
	}
	maxSize := int64(s.cfg.MaxUploadSizeMB) * 1024 * 1024
	s.mu.RUnlock()

	user := currentUser

	// Assemble file inside the confined uploadRoot
	finalFile, err := uploadRoot.OpenFile("assembled", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		s.internalError(w, r, "Failed to create assembled file", err)
		return
	}
	var actualSize int64
	for i := 0; i < upload.TotalChunks; i++ {
		chunkFile, err := uploadRoot.Open(strconv.Itoa(i))
		if err != nil {
			finalFile.Close()
			s.internalError(w, r, "Failed to read chunk from disk", err)
			return
		}
		n, copyErr := io.Copy(finalFile, chunkFile)
		chunkFile.Close()
		if copyErr != nil {
			finalFile.Close()
			s.internalError(w, r, "Failed to write assembled file", copyErr)
			return
		}
		actualSize += n
		if maxSize > 0 && actualSize > maxSize {
			finalFile.Close()
			http.Error(w, "Assembled file exceeds maximum allowed size", http.StatusBadRequest)
			return
		}
	}
	if err := finalFile.Close(); err != nil {
		s.internalError(w, r, "Failed to finalize assembled file", err)
		return
	}

	if actualSize != upload.TotalSize {
		http.Error(w, "Assembled file size does not match declared total size", http.StatusBadRequest)
		return
	}
	if maxSize > 0 && actualSize > maxSize {
		http.Error(w, "Assembled file exceeds maximum allowed size", http.StatusBadRequest)
		return
	}
	if user.StorageQuotaMB > 0 {
		total, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
		if total+actualSize > int64(user.StorageQuotaMB)*1024*1024 {
			logger.Action("User '%s' chunked upload complete rejected: quota exceeded for file '%s' (%s)", user.Username, upload.OriginalName, logger.FormatBytes(actualSize))
			http.Error(w, "Storage quota exceeded", http.StatusForbidden)
			return
		}
	}

	// Re-open for storage provider
	assembledFile, err := uploadRoot.Open("assembled")
	if err != nil {
		s.internalError(w, r, "Failed to open assembled file", err)
		return
	}
	defer assembledFile.Close()

	urlPath := upload.URLPath
	explicitURLPath := urlPath != ""
	if !explicitURLPath {
		if upload.CustomName != "" {
			urlPath = slugifyURLPath(upload.CustomName)
		} else {
			urlPath = slugifyURLPath(upload.OriginalName)
		}
	}

	storageKey := newStorageKey()
	if err := st.Save(r.Context(), storageKey, assembledFile); err != nil {
		s.internalError(w, r, "Failed to save file to storage", err)
		return
	}
	f := &db.File{
		OriginalName: upload.OriginalName,
		CustomName:   upload.CustomName,
		URLPath:      urlPath,
		Size:         actualSize,
		IsPrivate:    upload.IsPrivate,
		StatsEnabled: upload.StatsEnabled,
		StorageType:  storageType,
		StoragePath:  storageKey,
		UserID:       upload.UserID,
	}
	if err := db.InsertFile(r.Context(), database, f); err != nil {
		if isUniqueConstraintError(err) {
			if !explicitURLPath {
				f.URLPath = appendRandomURLPathSuffix(urlPath)
				if retryErr := db.InsertFile(r.Context(), database, f); retryErr == nil {
					logger.Action("User '%s' completed chunked upload for '%s' (size: %s, storage: %s, path: %s, upload_id: %s)", user.Username, upload.OriginalName, logger.FormatBytes(actualSize), storageType, storageKey, req.UploadID)
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]bool{"success": true})
					return
				}
			}
			_ = st.Delete(r.Context(), storageKey)
			http.Error(w, "URL path already in use", http.StatusConflict)
			return
		}
		st.Delete(r.Context(), storageKey) // Rollback
		s.internalError(w, r, "Failed to save file metadata to database", err)
		return
	}
	logger.Action("User '%s' completed chunked upload for '%s' (size: %s, storage: %s, path: %s, upload_id: %s)", user.Username, upload.OriginalName, logger.FormatBytes(actualSize), storageType, storageKey, req.UploadID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) cleanupExpiredUploads(now time.Time) {
	var expiredIDs []string
	s.chunkMu.Lock()
	for id, u := range s.chunkUploads {
		if now.Sub(u.CreatedAt) > chunkUploadTTL {
			u.mu.Lock()
			if !u.Completing {
				u.Completing = true
				delete(s.chunkUploads, id)
				expiredIDs = append(expiredIDs, id)
			}
			u.mu.Unlock()
		}
	}
	s.chunkMu.Unlock()
	for _, id := range expiredIDs {
		_ = removeChunkUploadDir(id)
	}
	s.totpTempStore.Sweep(now)
	s.webAuthnTempStore.Sweep(now)
	s.login2FAStore.Sweep(now)
	s.recoveryCodeStore.Sweep(now)
}

func (s *Server) runBackgroundJanitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-ticker.C:
			s.cleanupExpiredUploads(now)
		}
	}
}
