package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/storage"
)

const (
	maxTotalChunks              = 10000
	maxConcurrentUploadsPerUser = 5
	chunkUploadTTL              = time.Hour
	defaultChunkSizeMB          = 10
	defaultMaxBodyBytes         = 1 << 20  // 1 MB default limit for non-upload routes
	maxJSONOrFormBodyBytes      = 64 << 10 // 64 KB limit for small JSON/form routes
	maxLogoUploadBytes          = 5 << 20  // 5 MB limit for custom logo uploads
)

// ChunkUpload holds metadata and progress of a chunked file upload
type ChunkUpload struct {
	mu            sync.Mutex
	ID            string
	StorageKey    string
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
	Staged        storage.StagedUpload
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

func (s *Server) createStagedUpload(ctx context.Context, st storage.Provider, uploadID string, storageKey string, totalSize int64, chunkSize int64) (storage.StagedUpload, error) {
	if sp, ok := st.(storage.StagedProvider); ok {
		return sp.CreateStaged(ctx, uploadID, storageKey, totalSize, chunkSize)
	}
	return storage.NewDiskFallbackStagedUpload(chunkBaseDir(), uploadID, storageKey, totalSize, st)
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

	uploadBudget := transferBudget(maxSize)
	if maxSize <= 0 {
		uploadBudget = transferBudget(50 << 20)
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(uploadBudget))
	_ = rc.SetWriteDeadline(time.Now().Add(uploadBudget))

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

	user, err := s.currentUser(r)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := user.Username

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

	st, actualDriveID, err := s.getUploadProvider(driveID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Storage drive error: %v", err), http.StatusBadRequest)
		return
	}
	storageType := actualDriveID

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
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

	user, err := s.currentUser(r)
	if err != nil || user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := user.Username
	if maxSize > 0 && req.TotalSize > maxSize {
		logger.Action("User '%s' chunked upload init rejected: file '%s' exceeds maximum allowed size (%d MB)", username, req.FileName, maxUploadMB)
		http.Error(w, "File exceeds maximum allowed size", http.StatusBadRequest)
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
	s.chunkMu.Unlock()

	uploadID := newUploadID()
	storageKey := newStorageKey()

	st, actualDriveID, err := s.getUploadProvider(req.DriveID)
	if err != nil {
		http.Error(w, fmt.Sprintf("Storage drive error: %v", err), http.StatusBadRequest)
		return
	}
	req.DriveID = actualDriveID

	staged, err := s.createStagedUpload(r.Context(), st, uploadID, storageKey, req.TotalSize, chunkSize)
	if err != nil {
		s.internalError(w, r, "Failed to initialize staged upload", err)
		return
	}

	upload := &ChunkUpload{
		ID:           uploadID,
		StorageKey:   storageKey,
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
		CreatedAt:    now,
		Staged:       staged,
	}

	s.chunkMu.Lock()
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
	currentUser, err := s.currentUser(r)
	if err != nil || currentUser == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	maxChunkBytes := s.configuredChunkSizeBytes()
	chunkBudget := transferBudget(maxChunkBytes)
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(chunkBudget))
	_ = rc.SetWriteDeadline(time.Now().Add(chunkBudget))

	r.Body = http.MaxBytesReader(w, r.Body, maxChunkBytes+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Invalid multipart form", http.StatusBadRequest)
		return
	}

	var uploadID string
	chunkIndex := -1
	var chunkReader io.Reader
	var spoolFile *os.File

	if qID := r.URL.Query().Get("upload_id"); qID != "" {
		uploadID = qID
	}
	if qIdx := r.URL.Query().Get("chunk_index"); qIdx != "" {
		if idx, err := strconv.Atoi(qIdx); err == nil {
			chunkIndex = idx
		}
	}

	for {
		part, err := mr.NextPart()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if isMaxBytesError(err) {
				if spoolFile != nil {
					_ = spoolFile.Close()
					_ = os.Remove(spoolFile.Name())
				}
				http.Error(w, "Chunk exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
				return
			}
			if spoolFile != nil {
				_ = spoolFile.Close()
				_ = os.Remove(spoolFile.Name())
			}
			http.Error(w, "Failed to read chunk", http.StatusBadRequest)
			return
		}

		formName := part.FormName()
		switch formName {
		case "upload_id":
			b, _ := io.ReadAll(io.LimitReader(part, 128))
			uploadID = strings.TrimSpace(string(b))
		case "chunk_index":
			b, _ := io.ReadAll(io.LimitReader(part, 32))
			if idx, parseErr := strconv.Atoi(strings.TrimSpace(string(b))); parseErr == nil {
				chunkIndex = idx
			}
		case "chunk":
			if uploadID != "" && chunkIndex >= 0 {
				chunkReader = part
				goto streamChunk
			}
			spoolFile, err = os.CreateTemp(chunkBaseDir(), "spool_*")
			if err != nil {
				http.Error(w, "Failed to process chunk", http.StatusInternalServerError)
				return
			}
			defer func() {
				if spoolFile != nil {
					_ = spoolFile.Close()
					_ = os.Remove(spoolFile.Name())
				}
			}()
			if _, err := io.Copy(spoolFile, part); err != nil {
				if isMaxBytesError(err) {
					http.Error(w, "Chunk exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "Failed to read chunk", http.StatusBadRequest)
				return
			}
			if _, err := spoolFile.Seek(0, io.SeekStart); err != nil {
				http.Error(w, "Failed to process chunk", http.StatusInternalServerError)
				return
			}
			chunkReader = spoolFile
		default:
			_, _ = io.Copy(io.Discard, part)
		}
	}

streamChunk:
	if chunkReader == nil || uploadID == "" || chunkIndex < 0 {
		http.Error(w, "Invalid chunk submission or missing parameters", http.StatusBadRequest)
		return
	}

	s.chunkMu.RLock()
	upload, ok := s.chunkUploads[uploadID]
	s.chunkMu.RUnlock()

	if !ok || upload.UserID != currentUser.ID {
		_, _ = io.Copy(io.Discard, chunkReader)
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}

	if chunkIndex < 0 || chunkIndex >= upload.TotalChunks {
		_, _ = io.Copy(io.Discard, chunkReader)
		http.Error(w, "Chunk index out of bounds", http.StatusBadRequest)
		return
	}

	chunkLimit := upload.ChunkSize
	if chunkLimit <= 0 {
		chunkLimit = maxChunkBytes
	}

	upload.mu.Lock()
	if upload.Completing {
		upload.mu.Unlock()
		_, _ = io.Copy(io.Discard, chunkReader)
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}
	upload.mu.Unlock()

	offset := int64(chunkIndex) * upload.ChunkSize
	written, copyErr := upload.Staged.WriteChunk(r.Context(), chunkIndex, offset, chunkReader, chunkLimit)
	if copyErr != nil {
		if isMaxBytesError(copyErr) {
			http.Error(w, "Chunk exceeds maximum allowed size", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Failed to write chunk to storage", http.StatusBadRequest)
		return
	}
	if written > chunkLimit {
		http.Error(w, "Chunk exceeds maximum configured chunk size", http.StatusBadRequest)
		return
	}

	upload.mu.Lock()
	defer upload.mu.Unlock()
	if upload.Completing {
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}

	prevSize := upload.ChunkSizes[chunkIndex]
	newTotalReceived := upload.BytesReceived - prevSize + written
	if newTotalReceived > upload.TotalSize {
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
	currentUser, err := s.currentUser(r)
	if err != nil || currentUser == nil {
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

	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(transferBudget(upload.TotalSize)))

	st, actualDriveID, err := s.getUploadProvider(upload.DriveID)
	if err != nil {
		if upload.Staged != nil {
			_ = upload.Staged.Abort(r.Context())
		}
		http.Error(w, fmt.Sprintf("Storage drive error: %v", err), http.StatusInternalServerError)
		return
	}
	storageType := actualDriveID

	s.mu.RLock()
	maxSize := int64(s.cfg.MaxUploadSizeMB) * 1024 * 1024
	database := s.db
	s.mu.RUnlock()

	user := currentUser
	actualSize := upload.TotalSize

	if upload.BytesReceived != upload.TotalSize {
		if upload.Staged != nil {
			_ = upload.Staged.Abort(r.Context())
		}
		http.Error(w, "Assembled file size does not match declared total size", http.StatusBadRequest)
		return
	}

	if maxSize > 0 && actualSize > maxSize {
		if upload.Staged != nil {
			_ = upload.Staged.Abort(r.Context())
		}
		http.Error(w, "Assembled file exceeds maximum allowed size", http.StatusBadRequest)
		return
	}

	if user.StorageQuotaMB > 0 {
		total, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
		if total+actualSize > int64(user.StorageQuotaMB)*1024*1024 {
			if upload.Staged != nil {
				_ = upload.Staged.Abort(r.Context())
			}
			logger.Action("User '%s' chunked upload complete rejected: quota exceeded for file '%s' (%s)", user.Username, upload.OriginalName, logger.FormatBytes(actualSize))
			http.Error(w, "Storage quota exceeded", http.StatusForbidden)
			return
		}
	}

	urlPath := upload.URLPath
	explicitURLPath := urlPath != ""
	if !explicitURLPath {
		if upload.CustomName != "" {
			urlPath = slugifyURLPath(upload.CustomName)
		} else {
			urlPath = slugifyURLPath(upload.OriginalName)
		}
	}

	storageKey := upload.StorageKey
	if err := upload.Staged.Commit(r.Context(), storageKey, actualSize); err != nil {
		s.internalError(w, r, "Failed to commit file to storage", err)
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
	var expiredUploads []*ChunkUpload
	s.chunkMu.Lock()
	for id, u := range s.chunkUploads {
		if now.Sub(u.CreatedAt) > chunkUploadTTL {
			u.mu.Lock()
			if !u.Completing {
				u.Completing = true
				delete(s.chunkUploads, id)
				expiredUploads = append(expiredUploads, u)
			}
			u.mu.Unlock()
		}
	}
	s.chunkMu.Unlock()
	for _, u := range expiredUploads {
		if u.Staged != nil {
			_ = u.Staged.Abort(context.Background())
		}
		_ = removeChunkUploadDir(u.ID)
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
