package handlers

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fileline/auth"
	"fileline/database"
	"fileline/models"
	"fileline/storage"
)

/**
  GenerateID creates a compact random token for links, upload IDs, and file IDs.
  @param none - This function does not accept parameters.
  @returns string - The identifier string.
*/
func GenerateID() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 6)
	rand.Read(b)
	for i := range b {
		// Map random bytes into the allowed alphabet for URL-safe IDs.
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

/**
  GenerateBackupCode creates a human-transcribable recovery code.
  @param none - This function does not accept parameters.
  @returns string - The resulting string value.
*/
func GenerateBackupCode() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	// Format as XXXX-XXXX-XXXX-XXXX
	code := string(b)
	return code[0:4] + "-" + code[4:8] + "-" + code[8:12] + "-" + code[12:16]
}

/**
  ValidateLink enforces the public link character contract.
  @param link - The public link value.
  @returns bool - True when validate link is satisfied; otherwise false.
*/
func ValidateLink(link string) bool {
	for _, c := range link {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

type MissingFile struct {
	Path       string
	Name       string
	Size       int64
	ModifiedAt string
}

func localUploadsRoot(settings models.AppSettings) string {
	drive := storage.DriveByID(settings, models.LocalDriveID)
	root := strings.TrimSpace(drive.LocalPath)
	if root == "" {
		root = models.UploadsDir
	}
	return root
}

func findMissingLocalFiles(settings models.AppSettings, files []models.FileEntry) ([]MissingFile, error) {
	existing := make(map[string]bool, len(files))
	for _, file := range files {
		storage.ApplyFileDefaults(&file)
		driveID := strings.ToLower(strings.TrimSpace(file.DriveID))
		if driveID == "" || driveID == models.LocalDriveID {
			storagePath := strings.TrimSpace(file.StoragePath)
			if storagePath == "" {
				continue
			}
			normalized := path.Clean(filepath.ToSlash(storagePath))
			normalized = strings.TrimPrefix(normalized, "./")
			if normalized != "." && normalized != "" {
				existing[normalized] = true
			}
		}
	}

	root := localUploadsRoot(settings)
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return []MissingFile{}, nil
		}
		return nil, err
	}

	missing := []MissingFile{}
	err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		relPath = path.Clean(filepath.ToSlash(relPath))
		relPath = strings.TrimPrefix(relPath, "./")
		if relPath == "." || relPath == "" {
			return nil
		}
		if existing[relPath] {
			return nil
		}
		missing = append(missing, MissingFile{
			Path:       relPath,
			Name:       filepath.Base(relPath),
			Size:       info.Size(),
			ModifiedAt: info.ModTime().UTC().Format(time.RFC3339),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(missing, func(i, j int) bool {
		return missing[i].Path < missing[j].Path
	})
	return missing, nil
}

func generateUniqueLink() (string, error) {
	const maxAttempts = 6
	for i := 0; i < maxAttempts; i++ {
		link := GenerateID()
		if !database.LinkExists(link) {
			return link, nil
		}
	}
	return "", fmt.Errorf("failed to generate unique link")
}

func detectServedContentType(ext string) string {
	contentType := mime.TypeByExtension(strings.ToLower(ext))
	if contentType != "" {
		return contentType
	}
	return "application/octet-stream"
}

func shouldServeAsAttachment(ext string, contentType string) bool {
	unsafeExtensions := map[string]bool{
		".html":  true,
		".htm":   true,
		".svg":   true,
		".js":    true,
		".mjs":   true,
		".xhtml": true,
	}
	if unsafeExtensions[strings.ToLower(ext)] {
		return true
	}

	contentType = strings.ToLower(strings.TrimSpace(contentType))
	if contentType == "" || contentType == "application/octet-stream" {
		return true
	}
	if strings.HasPrefix(contentType, "text/html") || strings.HasPrefix(contentType, "image/svg+xml") || strings.Contains(contentType, "javascript") {
		return true
	}
	return false
}

/**
  HandleHome renders the dashboard with the most recent files and app settings.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		RenderHTTPError(w, r, http.StatusNotFound, "The page you requested was not found.")
		return
	}

	// Check database connection first
	if !CheckDatabaseConnection(w, r) {
		return
	}

	if auth.RequireSetup(w, r) {
		return
	}

	if auth.RequireAuth(w, r) {
		return
	}

	files := database.GetFiles()

	// Sort newest-first so dashboard and file list semantics stay consistent.
	sort.Slice(files, func(i, j int) bool {
		return files[i].UploadedAt > files[j].UploadedAt
	})

	latestFiles := files
	if len(latestFiles) > 10 {
		latestFiles = latestFiles[:10]
	}
	settings := database.GetSettings()

	data := map[string]interface{}{
		"Files":        latestFiles,
		"LoggedIn":     true,
		"Settings":     settings,
		"UploadDrives": storage.UploadDrives(settings),
		"CSRFToken":    auth.CSRFToken(r),
		"T":            T(),
	}

	Templates.ExecuteTemplate(w, "home.html", data)
}

/**
  HandleUpload processes standard (non-chunked) multipart uploads.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleUpload(w http.ResponseWriter, r *http.Request) {
	// Check database connection first
	if !CheckDatabaseConnection(w, r) {
		return
	}

	if auth.RequireSetup(w, r) {
		return
	}

	if auth.RequireAuth(w, r) {
		return
	}

	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	Debugf("HandleUpload request received")
	if !auth.AllowUploadRequest(r) {
		Debugf("HandleUpload rejected by upload limiter")
		RenderHTTPError(w, r, http.StatusTooManyRequests, "Too many upload requests")
		return
	}

	// Check max file size and resolve target upload drive from settings
	settings := database.GetSettings()
	maxFileSize := settings.MaxFileSize

	// Keep multipart parser memory bounded; large bodies spill to temporary files.
	r.ParseMultipartForm(100 << 20)

	file, header, err := r.FormFile("file")
	if err != nil {
		RenderHTTPError(w, r, http.StatusBadRequest, "Failed to read file")
		return
	}
	defer file.Close()

	// Validate file size
	if maxFileSize > 0 && header.Size > maxFileSize {
		Debugf("HandleUpload rejected oversized file=%q size=%d max=%d", header.Filename, header.Size, maxFileSize)
		RenderHTTPError(w, r, http.StatusBadRequest, "File too large")
		return
	}

	isPrivate := r.FormValue("public") != "on"
	customLink := strings.TrimSpace(r.FormValue("custom_link"))
	drive, err := storage.ResolveUploadDrive(settings, r.FormValue("drive_id"))
	if err != nil {
		RenderHTTPError(w, r, http.StatusBadRequest, "Invalid upload drive")
		return
	}

	link := customLink
	if link == "" {
		link = GenerateID()
	} else if !ValidateLink(link) {
		RenderHTTPError(w, r, http.StatusBadRequest, "Custom link can only contain A-Za-z0-9")
		return
	}

	if database.LinkExists(link) {
		Debugf("HandleUpload rejected duplicate link=%q", link)
		RenderHTTPError(w, r, http.StatusBadRequest, "Link already exists")
		return
	}

	fileID := GenerateID()
	storagePath := storage.BuildStoragePath(fileID, header.Filename)
	if err := storage.Put(context.Background(), drive, storagePath, file, header.Size); err != nil {
		RenderHTTPError(w, r, http.StatusInternalServerError, "Failed to save file")
		return
	}
	size := header.Size
	if size < 0 {
		size = 0
	}

	entry := models.FileEntry{
		ID:          fileID,
		Name:        header.Filename,
		Link:        link,
		Size:        size,
		UploadedAt:  time.Now().Format(time.RFC3339),
		IsPrivate:   isPrivate,
		DriveID:     drive.ID,
		StoragePath: storagePath,
	}

	database.AddFile(entry)
	Debugf("HandleUpload stored file id=%s name=%q link=%q private=%t size=%d", fileID, header.Filename, link, isPrivate, size)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

/**
  HandleFiles renders the full file catalog page for authenticated users.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleFiles(w http.ResponseWriter, r *http.Request) {
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	files := database.GetFiles()
	sort.Slice(files, func(i, j int) bool {
		return files[i].UploadedAt > files[j].UploadedAt
	})
	settings := database.GetSettings()
	rescanUploads := strings.TrimSpace(r.URL.Query().Get("rescan")) != ""
	missingFiles := []MissingFile{}
	if rescanUploads {
		var err error
		missingFiles, err = findMissingLocalFiles(settings, files)
		if err != nil {
			RenderHTTPError(w, r, http.StatusInternalServerError, "Failed to scan uploads folder")
			return
		}
	}
	flashMessage := r.URL.Query().Get("message")
	data := map[string]interface{}{
		"Files":        files,
		"MissingFiles": missingFiles,
		"MissingScan":  rescanUploads,
		"FlashMessage": flashMessage,
		"LoggedIn":     true,
		"Settings":     settings,
		"CSRFToken":    auth.CSRFToken(r),
		"T":            T(),
	}
	Templates.ExecuteTemplate(w, "files.html", data)
}

func HandleFilesImport(w http.ResponseWriter, r *http.Request) {
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		RenderHTTPError(w, r, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !auth.ValidateCSRFRequest(r, database.Config.IsBehindProxy) {
		Debugf("HandleFilesImport rejected due to CSRF validation failure")
		RenderHTTPError(w, r, http.StatusForbidden, "Forbidden")
		return
	}
	if err := r.ParseForm(); err != nil {
		RenderHTTPError(w, r, http.StatusBadRequest, "Failed to read import request")
		return
	}
	selected := r.Form["missing_files"]
	if len(selected) == 0 {
		http.Redirect(w, r, "/files", http.StatusSeeOther)
		return
	}

	settings := database.GetSettings()
	files := database.GetFiles()
	missingFiles, err := findMissingLocalFiles(settings, files)
	if err != nil {
		RenderHTTPError(w, r, http.StatusInternalServerError, "Failed to scan uploads folder")
		return
	}
	missingByPath := make(map[string]MissingFile, len(missingFiles))
	for _, missing := range missingFiles {
		missingByPath[missing.Path] = missing
	}

	uniqueSelections := make(map[string]MissingFile, len(selected))
	for _, selectedPath := range selected {
		missing, ok := missingByPath[selectedPath]
		if !ok {
			RenderHTTPError(w, r, http.StatusBadRequest, "Selected file is no longer available")
			return
		}
		uniqueSelections[selectedPath] = missing
	}

	var importErrors []string
	importedCount := 0

	for _, missing := range uniqueSelections {
		// Generate unique link with retry
		var link string
		var linkErr error
		for attempt := 0; attempt < 6; attempt++ {
			link = GenerateID()
			if !database.LinkExists(link) {
				linkErr = nil
				break
			}
			linkErr = fmt.Errorf("link %s already exists", link)
		}
		if linkErr != nil {
			importErrors = append(importErrors, fmt.Sprintf("%s: %v", missing.Name, linkErr))
			continue
		}

		uploadedAt := missing.ModifiedAt
		if uploadedAt == "" {
			uploadedAt = time.Now().UTC().Format(time.RFC3339)
		}

		// Normalize storage path (remove any leading "./" or "../")
		storagePath := path.Clean(missing.Path)
		storagePath = strings.TrimPrefix(storagePath, "./")

		entry := models.FileEntry{
			ID:          GenerateID(),
			Name:        missing.Name,
			Link:        link,
			Size:        missing.Size,
			UploadedAt:  uploadedAt,
			IsPrivate:   true, // imported files are private by default
			DriveID:     models.LocalDriveID,
			StoragePath: storagePath,
		}
		database.AddFile(entry)
		importedCount++
	}

	message := fmt.Sprintf("Successfully imported %d file(s).", importedCount)
	if len(importErrors) > 0 {
		message += " Errors: " + strings.Join(importErrors, "; ")
	}
	http.Redirect(w, r, "/files?message="+url.QueryEscape(message), http.StatusSeeOther)
}

/**
  HandleFileEdit validates and persists mutable metadata for one file.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleFileEdit(w http.ResponseWriter, r *http.Request) {
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	fileID := strings.TrimPrefix(r.URL.Path, "/file/edit/")
	trans := T()
	settings := database.GetSettings()
	file := database.GetFileByID(fileID)
	if file == nil {
		RenderHTTPError(w, r, http.StatusNotFound, "File not found")
		return
	}
	editT := trans["edit"].(map[string]interface{})
	if r.Method == http.MethodPost {
		newName := strings.TrimSpace(r.FormValue("name"))
		newLink := strings.TrimSpace(r.FormValue("link"))
		isPrivate := r.FormValue("public") != "on"
		// Prefer explicit hidden value when provided by the form.
		switch strings.ToLower(strings.TrimSpace(r.FormValue("is_private"))) {
		case "1", "true", "yes", "on":
			isPrivate = true
		case "0", "false", "no", "off":
			isPrivate = false
		}
		if newName == "" || newLink == "" {
			data := map[string]interface{}{
				"File":     file,
				"Error":    editT["error_required"],
				"LoggedIn": true,
				"Settings": settings,
				"T":        trans,
			}
			Templates.ExecuteTemplate(w, "edit.html", data)
			return
		}
		if !ValidateLink(newLink) {
			data := map[string]interface{}{
				"File":     file,
				"Error":    editT["error_format"],
				"LoggedIn": true,
				"Settings": settings,
				"T":        trans,
			}
			Templates.ExecuteTemplate(w, "edit.html", data)
			return
		}
		// Check if link already exists (excluding current file)
		linkTaken := false
		files := database.GetFiles()
		for _, f := range files {
			if f.Link == newLink && f.ID != fileID {
				linkTaken = true
				break
			}
		}
		if linkTaken {
			data := map[string]interface{}{
				"File":     file,
				"Error":    editT["error_exists"],
				"LoggedIn": true,
				"Settings": settings,
				"T":        trans,
			}
			Templates.ExecuteTemplate(w, "edit.html", data)
			return
		}
		if !database.UpdateFile(fileID, newName, newLink, isPrivate) {
			errorMessage := "Failed to update file"
			if localized, ok := editT["error_update"].(string); ok && localized != "" {
				errorMessage = localized
			}
			data := map[string]interface{}{
				"File":     file,
				"Error":    errorMessage,
				"LoggedIn": true,
				"Settings": settings,
				"T":        trans,
			}
			Templates.ExecuteTemplate(w, "edit.html", data)
			return
		}
		database.SaveDatabase()
		// Prevent false-success redirects when backend normalization silently diverges.
		updatedFile := database.GetFileByID(fileID)
		if updatedFile == nil || updatedFile.IsPrivate != isPrivate || updatedFile.Name != newName || updatedFile.Link != newLink {
			errorMessage := "Failed to update file"
			if localized, ok := editT["error_update"].(string); ok && localized != "" {
				errorMessage = localized
			}
			data := map[string]interface{}{
				"File":     file,
				"Error":    errorMessage,
				"LoggedIn": true,
				"Settings": settings,
				"T":        trans,
			}
			Templates.ExecuteTemplate(w, "edit.html", data)
			return
		}
		http.Redirect(w, r, "/files", http.StatusSeeOther)
		return
	}
	data := map[string]interface{}{
		"File":     file,
		"LoggedIn": true,
		"Settings": settings,
		"T":        trans,
	}
	Templates.ExecuteTemplate(w, "edit.html", data)
}

/**
  HandleFileDelete removes both file metadata and stored file content.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleFileDelete(w http.ResponseWriter, r *http.Request) {
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		RenderHTTPError(w, r, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !auth.ValidateCSRFRequest(r, database.Config.IsBehindProxy) {
		Debugf("HandleFileDelete rejected due to CSRF validation failure")
		RenderHTTPError(w, r, http.StatusForbidden, "Forbidden")
		return
	}
	fileID := strings.TrimPrefix(r.URL.Path, "/file/delete/")
	file := database.GetFileByID(fileID)
	if file == nil {
		RenderHTTPError(w, r, http.StatusNotFound, "File not found")
		return
	}
	settings := database.GetSettings()
	drive := storage.DriveByID(settings, file.DriveID)
	if err := storage.Delete(context.Background(), drive, file.StoragePath); err != nil {
		RenderHTTPError(w, r, http.StatusInternalServerError, "Failed to delete file from storage")
		return
	}
	if !database.DeleteFile(fileID) {
		RenderHTTPError(w, r, http.StatusNotFound, "File not found")
		return
	}
	database.SaveDatabase()
	Debugf("HandleFileDelete removed file id=%s drive=%s path=%q", fileID, drive.ID, file.StoragePath)
	http.Redirect(w, r, "/files", http.StatusSeeOther)
}

/**
  HandleFileAccess serves files by public link while preserving private-file access rules.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleFileAccess(w http.ResponseWriter, r *http.Request) {
	link := strings.TrimPrefix(r.URL.Path, "/f/")
	file := database.GetFileByLink(link)
	// Return same error for non-existent and private files (prevents URL scanning)
	if file == nil || (file.IsPrivate && !auth.IsLoggedIn(r)) {
		Debugf("HandleFileAccess denied for link=%q", link)
		w.WriteHeader(http.StatusForbidden)
		Templates.ExecuteTemplate(w, "403.html", map[string]interface{}{
			"T":        T(),
			"Settings": database.GetSettings(),
		})
		return
	}
	ext := filepath.Ext(file.Name)
	contentType := detectServedContentType(ext)
	disposition := "inline"
	if shouldServeAsAttachment(ext, contentType) {
		disposition = "attachment"
	}

	settings := database.GetSettings()
	drive := storage.DriveByID(settings, file.DriveID)
	reader, err := storage.Open(context.Background(), drive, file.StoragePath)
	if err != nil {
		RenderHTTPError(w, r, http.StatusNotFound, "File not found in storage")
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=%q", disposition, file.Name))
	Debugf("HandleFileAccess serving link=%q id=%s drive=%s disposition=%s", link, file.ID, drive.ID, disposition)
	if _, err := io.Copy(w, reader); err != nil {
		Debugf("HandleFileAccess streaming failed link=%q: %v", link, err)
	}
}
