package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"fileline/auth"
	"fileline/database"
	"fileline/models"
)

/**
  HandleStats returns aggregate file metrics for the authenticated dashboard.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleStats(w http.ResponseWriter, r *http.Request) {
	if !auth.IsLoggedIn(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	files := database.GetFiles()
	var totalSize int64
	for _, f := range files {
		totalSize += f.Size
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"file_count":      len(files),
		"total_size":      totalSize,
		"total_size_text": formatSizeAPI(totalSize),
	})
}

/**
  formatSizeAPI renders byte counts for API/UI display in consistent units.
  @param size - The size in bytes.
  @returns string - The resulting string value.
*/
func formatSizeAPI(size int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case size >= TB:
		return fmt.Sprintf("%.2f TB", float64(size)/float64(TB))
	case size >= GB:
		return fmt.Sprintf("%.2f GB", float64(size)/float64(GB))
	case size >= MB:
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	case size >= KB:
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	default:
		return fmt.Sprintf("%d B", size)
	}
}

/**
  HandleAPISettings returns effective application settings for authenticated clients.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleAPISettings(w http.ResponseWriter, r *http.Request) {
	if !auth.IsLoggedIn(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	settings := database.GetSettings()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"theme":           settings.Theme,
		"accent_color":    settings.AccentColor,
		"language":        settings.Language,
		"chunk_threshold": settings.ChunkThreshold,
		"chunk_size":      settings.ChunkSizeBytes,
		"max_file_size":   settings.MaxFileSize,
		"custom_logo":     settings.CustomLogo,
	})
}

/**
  HandleChunkInit creates server-side tracking state for a chunked upload session.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleChunkInit(w http.ResponseWriter, r *http.Request) {
	if !auth.IsLoggedIn(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !auth.AllowUploadRequest(r) {
		Debugf("HandleChunkInit rejected by upload limiter")
		http.Error(w, "Too many upload requests", http.StatusTooManyRequests)
		return
	}
	var req struct {
		FileName    string `json:"file_name"`
		TotalSize   int64  `json:"total_size"`
		TotalChunks int    `json:"total_chunks"`
		IsPrivate   bool   `json:"is_private"`
		CustomLink  string `json:"custom_link"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Debugf("HandleChunkInit invalid request payload: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	// Enforce configured upload limits before allocating temp storage.
	maxFileSize := database.GetSettings().MaxFileSize
	if maxFileSize > 0 && req.TotalSize > maxFileSize {
		Debugf("HandleChunkInit rejected oversized file=%q size=%d max=%d", req.FileName, req.TotalSize, maxFileSize)
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}
	if len(database.GetChunkUploads()) >= auth.MaxConcurrentChunkUploads {
		Debugf("HandleChunkInit rejected due to concurrent upload limit")
		http.Error(w, "Too many concurrent chunk uploads", http.StatusTooManyRequests)
		return
	}
	uploadID := GenerateID()
	tempDir := filepath.Join(models.ChunksDir, uploadID)
	os.MkdirAll(tempDir, 0755)
	// Preserve caller-supplied link when provided; otherwise generate one.
	link := req.CustomLink
	if link == "" {
		link = GenerateID()
	}
	if database.LinkExists(link) {
		Debugf("HandleChunkInit rejected duplicate link=%q", link)
		http.Error(w, "Link already exists", http.StatusBadRequest)
		return
	}
	upload := models.ChunkUpload{
		ID:          uploadID,
		FileName:    req.FileName,
		TotalSize:   req.TotalSize,
		TotalChunks: req.TotalChunks,
		Received:    make([]bool, req.TotalChunks),
		IsPrivate:   req.IsPrivate,
		CustomLink:  link,
		TempDir:     tempDir,
		CreatedAt:   time.Now().Format(time.RFC3339),
	}
	database.AddChunkUpload(upload)
	Debugf("HandleChunkInit created upload id=%s file=%q chunks=%d size=%d", uploadID, req.FileName, req.TotalChunks, req.TotalSize)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"upload_id": uploadID,
		"link":      link,
	})
}

/**
  HandleChunkUpload persists a single chunk and marks it received in upload state.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleChunkUpload(w http.ResponseWriter, r *http.Request) {
	if !auth.IsLoggedIn(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !auth.AllowUploadRequest(r) {
		Debugf("HandleChunkUpload rejected by upload limiter")
		http.Error(w, "Too many upload requests", http.StatusTooManyRequests)
		return
	}
	// Parse multipart body with a bounded in-memory footprint.
	r.ParseMultipartForm(32 << 20)
	uploadID := r.FormValue("upload_id")
	chunkIndex, _ := strconv.Atoi(r.FormValue("chunk_index"))
	file, _, err := r.FormFile("chunk")
	if err != nil {
		Debugf("HandleChunkUpload failed reading chunk for upload=%q chunk=%d: %v", uploadID, chunkIndex, err)
		http.Error(w, "Failed to read chunk", http.StatusBadRequest)
		return
	}
	defer file.Close()
	upload := database.GetChunkUpload(uploadID)
	if upload == nil {
		Debugf("HandleChunkUpload upload not found id=%q", uploadID)
		http.Error(w, "Upload not found", http.StatusNotFound)
		return
	}
	// Chunks are stored by index in a per-upload temp directory for deterministic assembly.
	chunkPath := filepath.Join(upload.TempDir, fmt.Sprintf("%d", chunkIndex))
	dst, err := os.Create(chunkPath)
	if err != nil {
		Debugf("HandleChunkUpload failed saving chunk for upload=%q chunk=%d: %v", uploadID, chunkIndex, err)
		http.Error(w, "Failed to save chunk", http.StatusInternalServerError)
		return
	}
	io.Copy(dst, file)
	dst.Close()
	database.UpdateChunkReceived(uploadID, chunkIndex)
	Debugf("HandleChunkUpload stored chunk upload=%q chunk=%d", uploadID, chunkIndex)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

/**
  HandleChunkComplete verifies chunk completeness, assembles the final file,.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleChunkComplete(w http.ResponseWriter, r *http.Request) {
	if !auth.IsLoggedIn(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !auth.AllowUploadRequest(r) {
		Debugf("HandleChunkComplete rejected by upload limiter")
		http.Error(w, "Too many upload requests", http.StatusTooManyRequests)
		return
	}
	var req struct {
		UploadID string `json:"upload_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		Debugf("HandleChunkComplete invalid request payload: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	upload := database.GetChunkUpload(req.UploadID)
	if upload == nil {
		Debugf("HandleChunkComplete upload not found id=%q", req.UploadID)
		http.Error(w, "Upload not found", http.StatusNotFound)
		return
	}
	// Fail fast when any chunk is missing to prevent partial file publication.
	for i, received := range upload.Received {
		if !received {
			Debugf("HandleChunkComplete missing chunk upload=%q chunk=%d", req.UploadID, i)
			http.Error(w, fmt.Sprintf("Missing chunk %d", i), http.StatusBadRequest)
			return
		}
	}
	fileID := GenerateID()
	ext := filepath.Ext(upload.FileName)
	storedName := fileID + ext
	finalPath := filepath.Join(models.UploadsDir, storedName)
	finalFile, err := os.Create(finalPath)
	if err != nil {
		Debugf("HandleChunkComplete failed creating file for upload=%q: %v", req.UploadID, err)
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	var totalSize int64
	for i := 0; i < upload.TotalChunks; i++ {
		// Reassemble in strict index order to preserve original byte sequence.
		chunkPath := filepath.Join(upload.TempDir, fmt.Sprintf("%d", i))
		chunkData, _ := os.ReadFile(chunkPath)
		n, _ := finalFile.Write(chunkData)
		totalSize += int64(n)
	}
	finalFile.Close()
	os.RemoveAll(upload.TempDir)
	entry := models.FileEntry{
		ID:         fileID,
		Name:       upload.FileName,
		Link:       upload.CustomLink,
		Size:       totalSize,
		UploadedAt: time.Now().Format(time.RFC3339),
		IsPrivate:  upload.IsPrivate,
	}
	database.AddFile(entry)
	database.RemoveChunkUpload(req.UploadID)
	Debugf("HandleChunkComplete finalized upload=%q file_id=%s link=%q size=%d", req.UploadID, fileID, entry.Link, totalSize)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"file_id": fileID,
		"link":    entry.Link,
	})
}
