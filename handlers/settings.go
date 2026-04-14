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

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var accentColorRegex = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

/*
*

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
	data := map[string]interface{}{
		"LoggedIn":     true,
		"Settings":     database.GetSettings(),
		"TwoFAEnabled": database.GetUser() != nil && database.GetUser().TwoFAEnabled,
		"Success":      r.URL.Query().Get("success"),
		"T":            T(),
	}
	Templates.ExecuteTemplate(w, "settings.html", data)
}

/*
*

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

/*
*

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

/*
*

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
			http.Redirect(w, r, "/settings?success=2fa", http.StatusSeeOther)
			return
		}
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
		http.Error(w, "Failed to generate 2FA secret", http.StatusInternalServerError)
		return
	}
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

/*
*

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
	http.Redirect(w, r, "/settings?success=2fa_disabled", http.StatusSeeOther)
}

/*
*

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

/*
*

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

/*
*

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
	validLangs := map[string]bool{"en": true, "pl": true}
	if !validLangs[lang] {
		lang = "en"
	}
	settings := database.GetSettings()
	settings.Language = lang
	database.UpdateSettings(settings)
	http.Redirect(w, r, "/settings?success=language", http.StatusSeeOther)
}

/*
*

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
