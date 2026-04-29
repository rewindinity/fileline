package handlers

import (
	"encoding/base64"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"fileline/auth"
	"fileline/database"
	"fileline/models"
	"fileline/storage"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var accentColorRegex = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

/**
  configuredDriveByType returns the first enabled storage drive matching the specified type.
  @param settings - The application settings containing storage drive configurations.
  @param driveType - The storage drive type to search for (e.g., "s3", "ftp", "sftp").
  @returns *models.StorageDrive - A pointer to the matching StorageDrive, or nil if not found.
*/
func configuredDriveByType(settings models.AppSettings, driveType string) *models.StorageDrive {
	for i := range settings.StorageDrives {
		drive := settings.StorageDrives[i]
		if drive.ID == models.LocalDriveID {
			continue
		}
		if drive.Type == driveType {
			d := drive
			return &d
		}
	}
	return nil
}

/**
  HandleSettings renders the account and application settings page.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleSettings(w http.ResponseWriter, r *http.Request) {
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
	settings := database.GetSettings()
	data := map[string]interface{}{
		"LoggedIn":     true,
		"Settings":     settings,
		"TwoFAEnabled": database.GetUser() != nil && database.GetUser().TwoFAEnabled,
		"Success":      r.URL.Query().Get("success"),
		"Error":        r.URL.Query().Get("error"),
		"S3Drive":      configuredDriveByType(settings, models.StorageTypeS3),
		"FTPDrive":     configuredDriveByType(settings, models.StorageTypeFTP),
		"SFTPDrive":    configuredDriveByType(settings, models.StorageTypeSFTP),
		"T":            T(),
	}
	Templates.ExecuteTemplate(w, "settings.html", data)
}

/**
  HandlePasswordChange validates and applies a password update for the current user.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandlePasswordChange(w http.ResponseWriter, r *http.Request) {
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
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	trans := T()
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")
	user := database.GetUser()
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword))
	settings := database.GetSettings()
	twoFAEnabled := user != nil && user.TwoFAEnabled
	settingsT := trans["settings"].(map[string]interface{})
	if err != nil {
		data := map[string]interface{}{
			"LoggedIn":      true,
			"Settings":      settings,
			"TwoFAEnabled":  twoFAEnabled,
			"PasswordError": settingsT["password_error_current"],
			"T":             trans,
		}
		Templates.ExecuteTemplate(w, "settings.html", data)
		return
	}
	if newPassword != confirmPassword {
		data := map[string]interface{}{
			"LoggedIn":      true,
			"Settings":      settings,
			"TwoFAEnabled":  twoFAEnabled,
			"PasswordError": settingsT["password_error_mismatch"],
			"T":             trans,
		}
		Templates.ExecuteTemplate(w, "settings.html", data)
		return
	}
	if len(newPassword) < 6 {
		data := map[string]interface{}{
			"LoggedIn":      true,
			"Settings":      settings,
			"TwoFAEnabled":  twoFAEnabled,
			"PasswordError": settingsT["password_error_length"],
			"T":             trans,
		}
		Templates.ExecuteTemplate(w, "settings.html", data)
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	user = database.GetUser()
	user.PasswordHash = string(hash)
	database.SetUser(user)
	http.Redirect(w, r, "/settings?success=password", http.StatusSeeOther)
}

/**
  Handle2FASettings renders current two-factor authentication state.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func Handle2FASettings(w http.ResponseWriter, r *http.Request) {
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	enabled := database.GetUser() != nil && database.GetUser().TwoFAEnabled
	settings := database.GetSettings()
	data := map[string]interface{}{
		"LoggedIn":     true,
		"TwoFAEnabled": enabled,
		"Settings":     settings,
		"T":            T(),
	}
	Templates.ExecuteTemplate(w, "2fa_settings.html", data)
}

/**
  Handle2FASetup performs TOTP enrollment and verification.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func Handle2FASetup(w http.ResponseWriter, r *http.Request) {
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	trans := T()
	username := database.GetUser().Username
	settings := database.GetSettings()
	twoFAT := trans["twofa"].(map[string]interface{})
	if r.Method == http.MethodPost {
		secret := r.FormValue("secret")
		code := strings.TrimSpace(r.FormValue("code"))
		if totp.Validate(code, secret) {
			user := database.GetUser()
			user.TwoFAEnabled = true
			user.TwoFASecret = secret
			database.SetUser(user)
			Debugf("2FA setup enabled for user=%q", username)
			http.Redirect(w, r, "/settings?success=2fa", http.StatusSeeOther)
			return
		}
		Debugf("2FA setup verification failed for user=%q", username)
		key, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "FileLine",
			AccountName: username,
		})
		data := map[string]interface{}{
			"LoggedIn": true,
			"Secret":   key.Secret(),
			"URL":      key.URL(),
			"Username": username,
			"Error":    twoFAT["error_invalid"],
			"Settings": settings,
			"T":        trans,
		}
		Templates.ExecuteTemplate(w, "2fa_setup.html", data)
		return
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "FileLine",
		AccountName: username,
	})
	if err != nil {
		RenderHTTPError(w, r, http.StatusInternalServerError, "Failed to generate 2FA secret")
		return
	}
	Debugf("2FA setup page generated for user=%q", username)
	data := map[string]interface{}{
		"LoggedIn": true,
		"Secret":   key.Secret(),
		"URL":      key.URL(),
		"Username": username,
		"Settings": settings,
		"T":        trans,
	}
	Templates.ExecuteTemplate(w, "2fa_setup.html", data)
}

/**
  Handle2FADisable requires a valid TOTP code before disabling 2FA.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func Handle2FADisable(w http.ResponseWriter, r *http.Request) {
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
		http.Redirect(w, r, "/settings/2fa", http.StatusSeeOther)
		return
	}
	trans := T()
	code := strings.TrimSpace(r.FormValue("code"))
	settings := database.GetSettings()
	secret := database.GetUser().TwoFASecret
	twoFAT := trans["twofa"].(map[string]interface{})
	if !totp.Validate(code, secret) {
		Debugf("2FA disable verification failed for user=%q", database.GetUser().Username)
		data := map[string]interface{}{
			"LoggedIn":     true,
			"TwoFAEnabled": true,
			"Error":        twoFAT["error_invalid"],
			"Settings":     settings,
			"T":            trans,
		}
		Templates.ExecuteTemplate(w, "2fa_settings.html", data)
		return
	}
	user := database.GetUser()
	user.TwoFAEnabled = false
	user.TwoFASecret = ""
	database.SetUser(user)
	Debugf("2FA disabled for user=%q", user.Username)
	http.Redirect(w, r, "/settings?success=2fa_disabled", http.StatusSeeOther)
}

/**
  HandleThemeSettings applies theme, accent, and optional custom-logo updates.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleThemeSettings(w http.ResponseWriter, r *http.Request) {
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	theme := r.FormValue("theme")
	accentColor := r.FormValue("accent_color")
	validThemes := map[string]bool{
		"dark-blue":   true,
		"dark-green":  true,
		"dark-orange": true,
		"dark-purple": true,
		"light":       true,
	}
	// Keep theme values on a strict allowlist to avoid persisting unexpected CSS keys.
	if !validThemes[theme] {
		theme = "dark-blue"
	}
	if !accentColorRegex.MatchString(accentColor) {
		accentColor = "#3b82f6"
	}
	settings := database.GetSettings()
	settings.Theme = theme
	settings.AccentColor = accentColor
	// Process logo upload only when a new file is supplied.
	file, header, err := r.FormFile("custom_logo")
	if err == nil && header != nil {
		defer file.Close()
		// Check file size (max 2MB)
		if header.Size > 2*1024*1024 {
			http.Redirect(w, r, "/settings?error=logo_too_large", http.StatusSeeOther)
			return
		}
		// Read and encode to base64
		buf, err := io.ReadAll(file)
		if err != nil {
			http.Redirect(w, r, "/settings?error=logo_read_failed", http.StatusSeeOther)
			return
		}
		if len(buf) > 2*1024*1024 {
			http.Redirect(w, r, "/settings?error=logo_too_large", http.StatusSeeOther)
			return
		}
		contentType := http.DetectContentType(buf)
		if contentType != "image/png" && contentType != "image/jpeg" && contentType != "image/webp" {
			http.Redirect(w, r, "/settings?error=invalid_logo_type", http.StatusSeeOther)
			return
		}
		// Persist as data URL so the active backend does not need binary/blob support.
		settings.CustomLogo = "data:" + contentType + ";base64," + base64.StdEncoding.EncodeToString(buf)
	}
	// Handle logo reset
	if r.FormValue("reset_logo") == "true" {
		settings.CustomLogo = ""
	}
	database.UpdateSettings(settings)
	http.Redirect(w, r, "/settings?success=theme", http.StatusSeeOther)
}

/**
  HandleUploadSettings updates chunking and file-size limits.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleUploadSettings(w http.ResponseWriter, r *http.Request) {
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	chunkThreshold, _ := strconv.ParseInt(r.FormValue("chunk_threshold"), 10, 64)
	chunkSize, _ := strconv.ParseInt(r.FormValue("chunk_size"), 10, 64)
	maxFileSize, _ := strconv.ParseInt(r.FormValue("max_file_size"), 10, 64)
	// Form values are submitted in MB; persist values in bytes.
	chunkThreshold = chunkThreshold * 1024 * 1024
	chunkSize = chunkSize * 1024 * 1024
	maxFileSize = maxFileSize * 1024 * 1024 // 0 means unlimited
	// Clamp to sane minimums to avoid degenerate chunk behavior.
	if chunkThreshold < 1024*1024 {
		chunkThreshold = models.DefaultChunkThreshold
	}
	if chunkSize < 1024*1024 {
		chunkSize = models.DefaultChunkSize
	}
	settings := database.GetSettings()
	settings.ChunkThreshold = chunkThreshold
	settings.ChunkSizeBytes = chunkSize
	settings.MaxFileSize = maxFileSize
	database.UpdateSettings(settings)
	http.Redirect(w, r, "/settings?success=upload", http.StatusSeeOther)
}

/**
  HandleLanguageSettings validates and applies a supported language code.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleLanguageSettings(w http.ResponseWriter, r *http.Request) {
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	lang := r.FormValue("language")
	validLangs := map[string]bool{"en": true, "pl": true, "de": true, "fr": true, "cz": true}
	if !validLangs[lang] {
		lang = "en"
	}
	settings := database.GetSettings()
	settings.Language = lang
	database.UpdateSettings(settings)
	http.Redirect(w, r, "/settings?success=language", http.StatusSeeOther)
}

/**
  HandleBackupCodeRegenerate rotates the account recovery backup code.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleBackupCodeRegenerate(w http.ResponseWriter, r *http.Request) {
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	user := database.GetUser()
	if user == nil {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	// Generate new backup code
	newBackupCode := GenerateBackupCode()
	user.BackupCode = newBackupCode
	database.SetUser(user)
	// Return the new backup code as JSON
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"backup_code":"` + newBackupCode + `"}`))
}

func parseToggle(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "1" || value == "true" || value == "on" || value == "yes"
}

func parsePortValue(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 {
		return fallback
	}
	return port
}

/**
  HandleStorageDrivesSettings updates optional external storage drive configuration.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleStorageDrivesSettings(w http.ResponseWriter, r *http.Request) {
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.RequireAuth(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	drives := make([]models.StorageDrive, 0, 3)

	if parseToggle(r.FormValue("s3_enabled")) {
		endpoint := strings.TrimSpace(r.FormValue("s3_endpoint"))
		bucket := strings.TrimSpace(r.FormValue("s3_bucket"))
		accessKey := strings.TrimSpace(r.FormValue("s3_access_key"))
		secretKey := strings.TrimSpace(r.FormValue("s3_secret_key"))
		if endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" {
			http.Redirect(w, r, "/settings?error=storage_s3", http.StatusSeeOther)
			return
		}
		name := strings.TrimSpace(r.FormValue("s3_name"))
		if name == "" {
			name = "S3 Drive"
		}
		drives = append(drives, models.StorageDrive{
			ID:           "s3-main",
			Name:         name,
			Type:         models.StorageTypeS3,
			Enabled:      true,
			S3Endpoint:   endpoint,
			S3Region:     strings.TrimSpace(r.FormValue("s3_region")),
			S3Bucket:     bucket,
			S3AccessKey:  accessKey,
			S3SecretKey:  secretKey,
			S3UseSSL:     parseToggle(r.FormValue("s3_use_ssl")),
			S3PathPrefix: strings.Trim(strings.TrimSpace(r.FormValue("s3_path_prefix")), "/"),
		})
	}

	if parseToggle(r.FormValue("ftp_enabled")) {
		host := strings.TrimSpace(r.FormValue("ftp_host"))
		username := strings.TrimSpace(r.FormValue("ftp_username"))
		password := strings.TrimSpace(r.FormValue("ftp_password"))
		if host == "" || username == "" || password == "" {
			http.Redirect(w, r, "/settings?error=storage_ftp", http.StatusSeeOther)
			return
		}
		name := strings.TrimSpace(r.FormValue("ftp_name"))
		if name == "" {
			name = "FTP Drive"
		}
		drives = append(drives, models.StorageDrive{
			ID:          "ftp-main",
			Name:        name,
			Type:        models.StorageTypeFTP,
			Enabled:     true,
			FTPHost:     host,
			FTPPort:     parsePortValue(r.FormValue("ftp_port"), 21),
			FTPUsername: username,
			FTPPassword: password,
			FTPBasePath: strings.Trim(strings.TrimSpace(r.FormValue("ftp_base_path")), "/"),
		})
	}

	if parseToggle(r.FormValue("sftp_enabled")) {
		host := strings.TrimSpace(r.FormValue("sftp_host"))
		username := strings.TrimSpace(r.FormValue("sftp_username"))
		password := strings.TrimSpace(r.FormValue("sftp_password"))
		if host == "" || username == "" || password == "" {
			http.Redirect(w, r, "/settings?error=storage_sftp", http.StatusSeeOther)
			return
		}
		name := strings.TrimSpace(r.FormValue("sftp_name"))
		if name == "" {
			name = "SFTP Drive"
		}
		drives = append(drives, models.StorageDrive{
			ID:           "sftp-main",
			Name:         name,
			Type:         models.StorageTypeSFTP,
			Enabled:      true,
			SFTPHost:     host,
			SFTPPort:     parsePortValue(r.FormValue("sftp_port"), 22),
			SFTPUsername: username,
			SFTPPassword: password,
			SFTPBasePath: strings.Trim(strings.TrimSpace(r.FormValue("sftp_base_path")), "/"),
		})
	}

	settings := database.GetSettings()
	settings.StorageDrives = models.NormalizeStorageDrives(drives)
	storage.NormalizeSettingsDrives(&settings)
	database.UpdateSettings(settings)
	http.Redirect(w, r, "/settings?success=storage", http.StatusSeeOther)
}
