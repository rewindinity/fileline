package handlers

import (
	"crypto/rand"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fileline/auth"
	"fileline/database"
	"fileline/models"
)

/*
*

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

/*
*

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

/*
*

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

/*
*

	HandleHome renders the dashboard with the most recent files and app settings.
	@param w - The HTTP response writer.
	@param r - The incoming HTTP request.
	@returns void
*/
func HandleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
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
		"Files":     latestFiles,
		"LoggedIn":  true,
		"Settings":  settings,
		"CSRFToken": auth.CSRFToken(r),
		"T":         T(),
	}

	Templates.ExecuteTemplate(w, "home.html", data)
}

/*
*

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
	if !auth.AllowUploadRequest(r) {
		http.Error(w, "Too many upload requests", http.StatusTooManyRequests)
		return
	}

	// Check max file size from settings
	maxFileSize := database.GetSettings().MaxFileSize

	// Keep multipart parser memory bounded; large bodies spill to temporary files.
	r.ParseMultipartForm(100 << 20)

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file size
	if maxFileSize > 0 && header.Size > maxFileSize {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	isPrivate := r.FormValue("public") != "on"
	customLink := strings.TrimSpace(r.FormValue("custom_link"))

	link := customLink
	if link == "" {
		link = GenerateID()
	} else if !ValidateLink(link) {
		http.Error(w, "Custom link can only contain A-Za-z0-9", http.StatusBadRequest)
		return
	}

	if database.LinkExists(link) {
		http.Error(w, "Link already exists", http.StatusBadRequest)
		return
	}

	fileID := GenerateID()
	ext := filepath.Ext(header.Filename)
	storedName := fileID + ext

	dst, err := os.Create(filepath.Join(models.UploadsDir, storedName))
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	size, err := io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	entry := models.FileEntry{
		ID:         fileID,
		Name:       header.Filename,
		Link:       link,
		Size:       size,
		UploadedAt: time.Now().Format(time.RFC3339),
		IsPrivate:  isPrivate,
	}

	database.AddFile(entry)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

/*
*

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
	data := map[string]interface{}{
		"Files":     files,
		"LoggedIn":  true,
		"Settings":  settings,
		"CSRFToken": auth.CSRFToken(r),
		"T":         T(),
	}
	Templates.ExecuteTemplate(w, "files.html", data)
}

/*
*

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
		http.NotFound(w, r)
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

/*
*

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
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !auth.ValidateCSRFRequest(r, database.Config.IsBehindProxy) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	fileID := strings.TrimPrefix(r.URL.Path, "/file/delete/")
	file := database.GetFileByID(fileID)
	if file == nil {
		http.NotFound(w, r)
		return
	}
	ext := filepath.Ext(file.Name)
	storedName := file.ID + ext
	if !database.DeleteFile(fileID) {
		http.NotFound(w, r)
		return
	}
	database.SaveDatabase()
	os.Remove(filepath.Join(models.UploadsDir, storedName))
	http.Redirect(w, r, "/files", http.StatusSeeOther)
}

/*
*

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
		w.WriteHeader(http.StatusForbidden)
		Templates.ExecuteTemplate(w, "403.html", map[string]interface{}{
			"T":        T(),
			"Settings": database.GetSettings(),
		})
		return
	}
	ext := filepath.Ext(file.Name)
	storedName := file.ID + ext
	filePath := filepath.Join(models.UploadsDir, storedName)

	contentType := detectServedContentType(ext)
	disposition := "inline"
	if shouldServeAsAttachment(ext, contentType) {
		disposition = "attachment"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("%s; filename=%q", disposition, file.Name))
	http.ServeFile(w, r, filePath)
}
