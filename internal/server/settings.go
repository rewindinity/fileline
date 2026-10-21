package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/storage"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) settingsHandler(w http.ResponseWriter, r *http.Request) {
	user, err := s.currentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := user.Username

	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()

	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")

	passkeysDisplay := formatPasskeysDisplay(user.WebAuthnData)

	var allUsers []*db.User
	if user.Role == "admin" {
		allUsers, _ = db.GetAllUsers(r.Context(), database)
	}
	s.renderTemplate(w, r, "settings.html", map[string]interface{}{
		"Title":          "Settings",
		"Username":       username,
		"User":           user,
		"AllUsers":       allUsers,
		"Passkeys":       passkeysDisplay,
		"Config":         cfg.SanitizedView(),
		"EnvOnly":        cfg.EnvOnly,
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
	})
}

func (s *Server) settingsAppearanceHandler(w http.ResponseWriter, r *http.Request) {
	user, err := s.currentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := user.Username
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, r, "settings_appearance.html", map[string]interface{}{
		"Title":          "Appearance Settings",
		"Username":       username,
		"User":           user,
		"Config":         cfg.SanitizedView(),
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
	})
}

func (s *Server) settingsEmbedHandler(w http.ResponseWriter, r *http.Request) {
	user, err := s.currentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := user.Username
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, r, "settings_embed.html", map[string]interface{}{
		"Title":          "Media Preview (Embed)",
		"Username":       username,
		"User":           user,
		"Config":         cfg.SanitizedView(),
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
	})
}

func (s *Server) settingsStorageHandler(w http.ResponseWriter, r *http.Request) {
	user, err := s.currentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := user.Username
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	if user.Role != "admin" {
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found"})
		return
	}
	drivesJSONBytes, _ := json.MarshalIndent(cfg.SanitizedDrives(), "", "  ")
	if string(drivesJSONBytes) == "null" {
		drivesJSONBytes = []byte("[]")
	}
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, r, "settings_storage.html", map[string]interface{}{
		"Title":          "Storage Settings",
		"Username":       username,
		"User":           user,
		"Config":         cfg.SanitizedView(),
		"DrivesJSON":     string(drivesJSONBytes),
		"EnvOnly":        cfg.EnvOnly,
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
	})
}

func (s *Server) settingsSubusersHandler(w http.ResponseWriter, r *http.Request) {
	user, err := s.currentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := user.Username
	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()
	if user.Role != "admin" {
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found"})
		return
	}
	allUsers, err := db.GetAllUsers(r.Context(), database)
	if err != nil {
		s.internalError(w, r, "Failed to load users from database", err)
		return
	}
	storageMap, err := db.GetAllUsersTotalStorage(r.Context(), database)
	if err != nil {
		s.internalError(w, r, "Failed to load storage totals from database", err)
		return
	}
	type userDisplay struct {
		User               *db.User
		FormattedTotalUsed string
	}
	var displayUsers []userDisplay
	for _, u := range allUsers {
		total := storageMap[u.ID]
		var formatted string
		if total < 1024*1024 {
			formatted = fmt.Sprintf("%.2f KB", float64(total)/1024)
		} else if total < 1024*1024*1024 {
			formatted = fmt.Sprintf("%.2f MB", float64(total)/(1024*1024))
		} else {
			formatted = fmt.Sprintf("%.2f GB", float64(total)/(1024*1024*1024))
		}
		displayUsers = append(displayUsers, userDisplay{
			User:               u,
			FormattedTotalUsed: formatted,
		})
	}
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, r, "settings_subusers.html", map[string]interface{}{
		"Title":          "Subusers Settings",
		"Username":       username,
		"User":           user,
		"Config":         cfg.SanitizedView(),
		"AllUsers":       displayUsers,
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
	})
}

// isValidLogoMagicBytes verifies that blob matches the expected magic signature for ext
func isValidLogoMagicBytes(ext string, blob []byte) bool {
	if len(blob) == 0 {
		return false
	}
	switch ext {
	case ".png":
		return len(blob) >= 8 &&
			blob[0] == 0x89 && blob[1] == 'P' && blob[2] == 'N' && blob[3] == 'G' &&
			blob[4] == '\r' && blob[5] == '\n' && blob[6] == 0x1a && blob[7] == '\n'
	case ".jpg", ".jpeg":
		return len(blob) >= 3 && blob[0] == 0xff && blob[1] == 0xd8 && blob[2] == 0xff
	case ".svg":
		trimmed := strings.TrimSpace(strings.ToLower(string(blob)))
		if !strings.Contains(trimmed, "<svg") {
			return false
		}
		// Reject SVG logos containing script tags, foreignObject, animations, or inline event handlers
		forbidden := []string{
			"<script", "</script", "javascript:", "onload", "onerror",
			"onclick", "onmouseover", "onfocus", "onblur", "onpointer",
			"<animate", "<set", "<foreignobject", "<use", "<handler",
		}
		for _, f := range forbidden {
			if strings.Contains(trimmed, f) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (s *Server) parseSettingsActionBody(w http.ResponseWriter, r *http.Request, action string) bool {
	if action == "appearance" {
		r.Body = http.MaxBytesReader(w, r.Body, maxLogoUploadBytes+maxJSONOrFormBodyBytes)
		ct := r.Header.Get("Content-Type")
		if strings.HasPrefix(strings.ToLower(ct), "multipart/form-data") {
			if err := r.ParseMultipartForm(maxLogoUploadBytes); err != nil {
				if isMaxBytesError(err) {
					http.Error(w, "Logo file exceeds maximum allowed size (1 MB)", http.StatusRequestEntityTooLarge)
					return false
				}
				http.Redirect(w, r, "/settings/appearance?error=Logo+file+too+large+or+invalid+form", http.StatusFound)
				return false
			}
		} else {
			if err := r.ParseForm(); err != nil {
				if isMaxBytesError(err) {
					http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
					return false
				}
				http.Redirect(w, r, "/settings/appearance?error=Invalid+form+submission", http.StatusFound)
				return false
			}
		}
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
		if err := r.ParseForm(); err != nil {
			if isMaxBytesError(err) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return false
			}
			http.Error(w, "Invalid form submission", http.StatusBadRequest)
			return false
		}
	}
	return true
}

func (s *Server) settingsActionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	user, err := s.currentUser(r)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	action := strings.TrimPrefix(r.URL.Path, "/settings/action/")
	if !s.parseSettingsActionBody(w, r, action) {
		return
	}

	switch action {
	case "storage":
		s.settingsActionStorage(w, r, user)
	case "appearance":
		s.settingsActionAppearance(w, r, user)
	case "indexing":
		s.settingsActionIndexing(w, r, user)
	case "compression":
		s.settingsActionCompression(w, r, user)
	case "embed":
		s.settingsActionEmbed(w, r, user)
	case "password":
		s.settingsActionPassword(w, r, user)
	default:
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
	}
}

func (s *Server) settingsActionStorage(w http.ResponseWriter, r *http.Request, user *db.User) {
	if user.Role != "admin" {
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found"})
		return
	}
	s.mu.Lock()
	if s.cfg.EnvOnly {
		s.mu.Unlock()
		http.Redirect(w, r, "/settings/storage?error=Cannot+modify+storage+in+ENV-only+mode", http.StatusFound)
		return
	}
	storageType := r.FormValue("storage_type")
	s.cfg.StorageType = storageType
	switch storageType {
	case "local":
		localPath := r.FormValue("local_path")
		if localPath == "" {
			localPath = "./uploads"
		}
		s.cfg.LocalStoragePath = localPath
	case "s3":
		s.cfg.S3Endpoint = r.FormValue("s3_endpoint")
		s.cfg.S3Region = r.FormValue("s3_region")
		s.cfg.S3Bucket = r.FormValue("s3_bucket")
		s.cfg.S3AccessKey = r.FormValue("s3_access_key")
		secret := r.FormValue("s3_secret_key")
		if secret != "" {
			s.cfg.S3SecretKey = secret
		}
		s.cfg.S3UseSSL = r.FormValue("s3_use_ssl") == "on"
	}
	if maxUpload, err := strconv.Atoi(r.FormValue("max_upload_size_mb")); err == nil {
		s.cfg.MaxUploadSizeMB = maxUpload
	}
	if threshold, err := strconv.Atoi(r.FormValue("chunk_threshold_mb")); err == nil {
		s.cfg.ChunkThresholdMB = threshold
	}
	if size, err := strconv.Atoi(r.FormValue("chunk_size_mb")); err == nil {
		s.cfg.ChunkSizeMB = size
	}
	drivesJSON := r.FormValue("drives_json")
	if drivesJSON != "" {
		var newDrives []config.Drive
		if err := json.Unmarshal([]byte(drivesJSON), &newDrives); err == nil {
			existingSecrets := make(map[string]string, len(s.cfg.Drives))
			for _, old := range s.cfg.Drives {
				if old.ID != "" && old.S3SecretKey != "" {
					existingSecrets[old.ID] = old.S3SecretKey
				}
			}
			for i := range newDrives {
				if newDrives[i].S3SecretKey == "" {
					if prev, ok := existingSecrets[newDrives[i].ID]; ok {
						newDrives[i].S3SecretKey = prev
					}
				}
			}
			s.cfg.Drives = newDrives
		} else {
			logger.Error("Failed to parse drives_json: %v", err)
		}
	}
	_ = s.saveConfigLocked()
	// Reinit storage
	st, err := storage.NewProvider(r.Context(), s.cfg)
	if err == nil {
		s.storage = st
	} else {
		logger.Error("Failed to reinitialize storage: %v", err)
	}
	s.initDrives(r.Context())
	s.mu.Unlock()
	logger.Action("User '%s' updated storage settings (type=%s, max_upload_size=%dMB, chunk_size=%dMB, chunk_threshold=%dMB)", user.Username, storageType, s.cfg.MaxUploadSizeMB, s.cfg.ChunkSizeMB, s.cfg.ChunkThresholdMB)
	http.Redirect(w, r, "/settings/storage?success=Storage+settings+saved", http.StatusFound)
}

func (s *Server) settingsActionAppearance(w http.ResponseWriter, r *http.Request, user *db.User) {
	theme := r.FormValue("theme")
	language := r.FormValue("language")
	var accent string
	if r.FormValue("use_global_accent") == "on" {
		accent = "global"
	} else {
		accent = strings.TrimSpace(r.FormValue("accent"))
	}
	if theme == "" {
		theme = "global"
	}
	if accent == "" {
		accent = "global"
	}
	if language == "" {
		language = "global"
	}
	if !isValidTheme(theme, true) {
		http.Redirect(w, r, "/settings/appearance?error=Invalid+theme", http.StatusFound)
		return
	}
	if accent != "global" && !isValidHexColor(accent) {
		http.Redirect(w, r, "/settings/appearance?error=Invalid+accent+color", http.StatusFound)
		return
	}
	if !isValidLanguage(language, true) {
		http.Redirect(w, r, "/settings/appearance?error=Invalid+language", http.StatusFound)
		return
	}

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	err := db.UpdateUserTheme(r.Context(), database, user.Username, theme, accent)
	if err != nil {
		http.Redirect(w, r, "/settings/appearance?error=Failed+to+update+theme", http.StatusFound)
		return
	}
	err = db.UpdateUserLanguage(r.Context(), database, user.Username, language)
	if err != nil {
		http.Redirect(w, r, "/settings/appearance?error=Failed+to+update+language", http.StatusFound)
		return
	}
	if user.Role == "admin" {
		globalTheme := strings.TrimSpace(r.FormValue("global_theme"))
		customAccentHex := strings.TrimSpace(r.FormValue("custom_accent_hex"))
		globalLanguage := strings.TrimSpace(r.FormValue("global_language"))
		if globalTheme != "" && !isValidTheme(globalTheme, false) {
			http.Redirect(w, r, "/settings/appearance?error=Invalid+global+theme", http.StatusFound)
			return
		}
		if customAccentHex != "" && !isValidHexColor(customAccentHex) {
			http.Redirect(w, r, "/settings/appearance?error=Invalid+global+accent+color", http.StatusFound)
			return
		}
		if globalLanguage != "" && !isValidLanguage(globalLanguage, false) {
			http.Redirect(w, r, "/settings/appearance?error=Invalid+global+language", http.StatusFound)
			return
		}
		s.mu.Lock()
		if globalTheme != "" {
			s.cfg.Theme = globalTheme
		}
		if customAccentHex != "" {
			s.cfg.CustomAccentHex = customAccentHex
		}
		if globalLanguage != "" {
			s.cfg.DefaultLanguage = globalLanguage
		}
		if r.FormValue("block_indexing_present") == "1" {
			s.cfg.BlockIndexing = r.FormValue("block_indexing") == "on"
		}
		if r.FormValue("compression_settings_present") == "1" {
			s.cfg.GzipEnabled = r.FormValue("gzip_enabled") == "on"
			s.cfg.MinifyResponses = r.FormValue("minify_responses") == "on"
		}
		_ = s.saveConfigLocked()
		s.mu.Unlock()

		// Handle custom logo upload
		if r.MultipartForm != nil {
			file, header, err := r.FormFile("custom_logo_file")
			if err == nil {
				defer file.Close()
				if header.Size > maxLogoUploadBytes {
					http.Redirect(w, r, "/settings/appearance?error=Logo+exceeds+maximum+size+of+1+MB", http.StatusFound)
					return
				}
				ext := strings.ToLower(filepath.Ext(header.Filename))
				if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".svg" {
					blob, ioErr := io.ReadAll(io.LimitReader(file, maxLogoUploadBytes+1))
					if ioErr != nil || int64(len(blob)) > maxLogoUploadBytes || len(blob) == 0 {
						logger.Error("ReadAll/size error for logo: err=%v, len=%d", ioErr, len(blob))
						http.Redirect(w, r, "/settings/appearance?error=Failed+to+read+logo+file+or+file+too+large", http.StatusFound)
						return
					}
					if !isValidLogoMagicBytes(ext, blob) {
						logger.Debug("Logo magic bytes check failed for extension %s", ext)
						http.Redirect(w, r, "/settings/appearance?error=Invalid+logo+file+content", http.StatusFound)
						return
					}
					filename := "custom-logo" + ext
					_ = os.MkdirAll("data", 0o750)
					writeErr := os.WriteFile(filepath.Join("data", filename), blob, 0o600)
					if writeErr == nil {
						s.mu.Lock()
						s.cfg.CustomLogo = filename
						_ = s.saveConfigLocked()
						s.mu.Unlock()
						logger.Action("User '%s' uploaded custom logo '%s'", user.Username, filename)
					} else {
						logger.Error("WriteFile error for logo: %v", writeErr)
						http.Redirect(w, r, "/settings/appearance?error=Failed+to+write+logo", http.StatusFound)
						return
					}
				} else {
					logger.Debug("Invalid logo extension: %s", ext)
					http.Redirect(w, r, "/settings/appearance?error=Invalid+logo+extension.+Only+PNG,+JPG,+SVG+allowed.", http.StatusFound)
					return
				}
			} else if err != http.ErrMissingFile {
				logger.Debug("FormFile error for logo: %v", err)
				http.Redirect(w, r, "/settings/appearance?error=Failed+to+process+logo+upload", http.StatusFound)
				return
			}
		}
	}

	logger.Action("User '%s' updated appearance settings (theme=%s, accent=%s, language=%s)", user.Username, theme, accent, language)
	http.Redirect(w, r, "/settings/appearance?success=Appearance+updated", http.StatusFound)
}

func (s *Server) settingsActionIndexing(w http.ResponseWriter, r *http.Request, user *db.User) {
	if user.Role != "admin" {
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found"})
		return
	}
	blockIndexing := r.FormValue("block_indexing") == "on"
	s.mu.Lock()
	s.cfg.BlockIndexing = blockIndexing
	_ = s.saveConfigLocked()
	s.mu.Unlock()
	logger.Action("User '%s' updated search engine indexing protection (block_indexing=%t)", user.Username, blockIndexing)
	http.Redirect(w, r, "/settings/account?success=Indexing+protection+settings+saved", http.StatusFound)
}

func (s *Server) settingsActionCompression(w http.ResponseWriter, r *http.Request, user *db.User) {
	if user.Role != "admin" {
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found"})
		return
	}
	gzipEnabled := r.FormValue("gzip_enabled") == "on"
	minifyResponses := r.FormValue("minify_responses") == "on"
	s.mu.Lock()
	s.cfg.GzipEnabled = gzipEnabled
	s.cfg.MinifyResponses = minifyResponses
	_ = s.saveConfigLocked()
	s.mu.Unlock()
	logger.Action("User '%s' updated compression settings (gzip_enabled=%t, minify_responses=%t)", user.Username, gzipEnabled, minifyResponses)
	http.Redirect(w, r, "/settings/appearance?success=Compression+settings+saved", http.StatusFound)
}

func (s *Server) settingsActionEmbed(w http.ResponseWriter, r *http.Request, user *db.User) {
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	color := strings.TrimSpace(r.FormValue("embed_color"))
	if color == "" {
		color = "#1d9bf0"
	}
	if !isValidHexColor(color) {
		http.Redirect(w, r, "/settings/embed?error=Invalid+embed+color", http.StatusFound)
		return
	}
	siteName := strings.TrimSpace(r.FormValue("embed_site_name"))
	customText := strings.TrimSpace(r.FormValue("embed_custom_text"))
	if len(siteName) > maxCustomNameLen || len(customText) > 500 {
		http.Redirect(w, r, "/settings/embed?error=Embed+text+exceeds+maximum+length", http.StatusFound)
		return
	}
	embedCfg := db.EmbedConfig{
		Enabled:        r.FormValue("embed_enabled") == "on",
		Color:          color,
		UseAccentColor: r.FormValue("embed_use_accent") == "on",
		SiteName:       siteName,
		CustomText:     customText,
		ShowTitle:      r.FormValue("embed_show_title") == "on",
		ShowSize:       r.FormValue("embed_show_size") == "on",
		ShowDate:       r.FormValue("embed_show_date") == "on",
		ShowAuthor:     r.FormValue("embed_show_author") == "on",
	}
	if err := db.UpdateUserEmbedConfig(r.Context(), database, user.Username, embedCfg); err != nil {
		http.Redirect(w, r, "/settings/embed?error=Failed+to+update+embed+settings", http.StatusFound)
		return
	}
	logger.Action("User '%s' updated personal media embed settings (enabled=%t, color=%s, use_accent=%t)", user.Username, embedCfg.Enabled, embedCfg.Color, embedCfg.UseAccentColor)
	http.Redirect(w, r, "/settings/embed?success=Embed+settings+saved", http.StatusFound)
}

func (s *Server) settingsActionPassword(w http.ResponseWriter, r *http.Request, user *db.User) {
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	if err := validatePassword(newPassword); err != nil {
		http.Redirect(w, r, "/settings/account?error="+strings.ReplaceAll(err.Error(), " ", "+"), http.StatusFound)
		return
	}
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
		logger.Action("User '%s' failed password change attempt (incorrect current password)", user.Username)
		http.Redirect(w, r, "/settings/account?error=Incorrect+current+password", http.StatusFound)
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		s.internalError(w, r, "Failed to hash new password", err)
		return
	}
	if err := db.UpdatePassword(r.Context(), database, user.Username, string(newHash)); err != nil {
		s.internalError(w, r, "Failed to update password in database", err)
		return
	}
	s.setJWTCookie(w, user.Username)
	logger.Action("User '%s' successfully changed their account password", user.Username)
	http.Redirect(w, r, "/settings/account?success=Password+updated+successfully", http.StatusFound)
}

func (s *Server) settingsRemoveLogoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
	user, err := s.currentUser(r)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := user.Username
	if user.Role != "admin" {
		http.Redirect(w, r, "/settings/appearance?error=Unauthorized", http.StatusFound)
		return
	}
	s.mu.Lock()
	oldLogo := s.cfg.CustomLogo
	s.cfg.CustomLogo = "/static/logo.svg"
	_ = s.saveConfigLocked()
	s.mu.Unlock()
	// Optionally delete the file
	if oldLogo != "" && oldLogo != "/static/logo.svg" {
		os.Remove(filepath.Join("data", oldLogo))
	}
	logger.Action("User '%s' removed custom logo, restored default logo", username)
	http.Redirect(w, r, "/settings/appearance?success=Custom+logo+removed", http.StatusFound)
}

func (s *Server) addUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		if isMaxBytesError(err) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	user, err := s.currentUser(r)
	if err != nil || user.Role != "admin" {
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found"})
		return
	}
	username := user.Username
	newUsername := strings.TrimSpace(r.FormValue("new_username"))
	newPassword := r.FormValue("new_password")
	rawQuota := strings.TrimSpace(r.FormValue("new_quota"))
	quotaMB := 0
	if rawQuota != "" {
		parsedQuota, qErr := strconv.Atoi(rawQuota)
		if qErr != nil || parsedQuota < 0 {
			http.Redirect(w, r, "/settings/subusers?error=Invalid+storage+quota", http.StatusFound)
			return
		}
		quotaMB = parsedQuota
	}
	if err := validateUsername(newUsername); err != nil {
		http.Redirect(w, r, "/settings/subusers?error="+strings.ReplaceAll(err.Error(), " ", "+"), http.StatusFound)
		return
	}
	if err := validatePassword(newPassword); err != nil {
		http.Redirect(w, r, "/settings/subusers?error="+strings.ReplaceAll(err.Error(), " ", "+"), http.StatusFound)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		s.internalError(w, r, "Failed to hash subuser password", err)
		return
	}
	if err := db.CreateSubuser(r.Context(), database, newUsername, string(hash), quotaMB); err != nil {
		if isUniqueConstraintError(err) {
			http.Redirect(w, r, "/settings/subusers?error=Username+already+exists", http.StatusFound)
			return
		}
		s.internalError(w, r, "Failed to create subuser in database", err)
		return
	}
	logger.Action("User '%s' created subuser '%s' (quota=%dMB)", username, newUsername, quotaMB)
	http.Redirect(w, r, "/settings/subusers?success=User+created+successfully", http.StatusFound)
}

func (s *Server) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
	if err := r.ParseForm(); err != nil {
		if isMaxBytesError(err) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid form submission", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := s.currentUser(r)
	if err != nil || user.Role != "admin" {
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
		return
	}
	username := user.Username
	targetUser := r.FormValue("username")
	if targetUser == username {
		http.Redirect(w, r, "/settings/subusers?error=Cannot+delete+yourself", http.StatusFound)
		return
	}
	if err := db.DeleteUser(r.Context(), database, targetUser); err != nil {
		s.internalError(w, r, "Failed to delete subuser from database", err)
		return
	}
	logger.Action("User '%s' deleted subuser '%s'", username, targetUser)
	http.Redirect(w, r, "/settings/subusers?success=User+deleted+successfully", http.StatusFound)
}
