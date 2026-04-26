package handlers

import (
	"crypto/subtle"
	"html/template"
	"net/http"
	"strings"
	"time"

	"fileline/auth"
	"fileline/database"
	"fileline/models"
	i18n "fileline/translations"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

var Templates *template.Template

/**
  CheckDatabaseConnection renders a 500 page when backend connectivity is unavailable.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns bool - True when check database connection is satisfied; otherwise false.
*/
func CheckDatabaseConnection(w http.ResponseWriter, r *http.Request) bool {
	if database.HasConnectionError() {
		RenderHTTPError(w, r, http.StatusInternalServerError, "Failed to connect to database")
		return false
	}
	return true
}

/**
  HandleSetup performs first-run provisioning: account creation, backend selection,.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleSetup(w http.ResponseWriter, r *http.Request) {
	// Check database connection first
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if database.IsConfigured() {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	// Get language from form or default
	lang := r.FormValue("language")
	if lang == "" {
		lang = "en"
	}
	trans := i18n.Get(lang)
	if r.Method == http.MethodPost {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		confirmPassword := r.FormValue("confirm_password")
		theme := r.FormValue("theme")
		dbType := r.FormValue("database")
		// Get database-specific connection details
		mongoURL := r.FormValue("mongo_url")
		pgHost := r.FormValue("pg_host")
		pgUser := r.FormValue("pg_user")
		pgDatabase := r.FormValue("pg_database")
		// Enforce strict allowlists for setup-controlled options.
		validThemes := map[string]bool{
			"dark-blue":   true,
			"dark-green":  true,
			"dark-orange": true,
			"dark-purple": true,
			"light":       true,
		}
		if !validThemes[theme] {
			theme = "dark-blue"
		}
		validLangs := map[string]bool{"en": true, "pl": true}
		if !validLangs[lang] {
			lang = "en"
		}
		validDBTypes := map[string]bool{"sqlite": true, "mongodb": true, "postgresql": true}
		if !validDBTypes[dbType] {
			dbType = "sqlite"
		}
		setupT := trans["setup"].(map[string]interface{})
		if username == "" || password == "" {
			Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{
				"Error": setupT["error_required"],
				"T":     trans,
				"Theme": theme,
				"Lang":  lang,
			})
			return
		}
		if password != confirmPassword {
			Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{
				"Error": setupT["error_mismatch"],
				"T":     trans,
				"Theme": theme,
				"Lang":  lang,
			})
			return
		}
		if len(password) < 6 {
			Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{
				"Error": setupT["error_min_length"],
				"T":     trans,
				"Theme": theme,
				"Lang":  lang,
			})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{
				"Error": setupT["error_hash"],
				"T":     trans,
				"Theme": theme,
				"Lang":  lang,
			})
			return
		}
		// Generate backup code for account recovery
		backupCode := GenerateBackupCode()
		user := &models.User{
			Username:     username,
			PasswordHash: string(hash),
			CreatedAt:    time.Now().Format(time.RFC3339),
			BackupCode:   backupCode,
		}
		// Persist connection settings before opening backend so setup survives restarts.
		database.Config.DatabaseType = dbType
		database.Config.MongoURL = mongoURL
		database.Config.PgHost = pgHost
		database.Config.PgUser = pgUser
		database.Config.PgDatabase = pgDatabase
		database.SaveConfig()
		// Initialize the database with selected type
		if err := database.InitDatabase(); err != nil {
			Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{
				"Error": "Database connection failed: " + err.Error(),
				"T":     trans,
				"Theme": theme,
				"Lang":  lang,
			})
			return
		}
		// Now save user and settings
		database.SetUser(user)
		settings := database.GetSettings()
		settings.Theme = theme
		settings.Language = lang
		settings.AccentColor = "#3b82f6"
		database.UpdateSettings(settings)
		database.SetConfigured(true)
		sessionID := auth.Store.Create(username, false)
		auth.SetSessionCookie(w, sessionID)
		// Show setup complete page with backup code
		Templates.ExecuteTemplate(w, "setup_complete.html", map[string]interface{}{
			"T":          trans,
			"Theme":      theme,
			"BackupCode": backupCode,
		})
		return
	}
	Templates.ExecuteTemplate(w, "setup.html", map[string]interface{}{
		"T":     trans,
		"Theme": "dark-blue",
		"Lang":  lang,
	})
}

/**
  HandleLogin validates credentials and establishes a new session (optionally pending 2FA).
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	// Check database connection first
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	if auth.IsLoggedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	trans := T()
	settings := database.GetSettings()
	if r.Method == http.MethodPost {
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		Debugf("Login attempt for user=%q", username)
		user := database.GetUser()
		loginT := trans["login"].(map[string]interface{})
		// Use the same generic message for unknown user and wrong password.
		if user == nil || user.Username != username {
			Debugf("Failed login for user=%q (unknown user or username mismatch)", username)
			auth.RecordFailedAttempt(r, database.Config.IsBehindProxy)
			Templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
				"Error":    loginT["error_invalid"],
				"T":        trans,
				"Settings": settings,
			})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			Debugf("Failed login for user=%q (invalid password)", username)
			auth.RecordFailedAttempt(r, database.Config.IsBehindProxy)
			Templates.ExecuteTemplate(w, "login.html", map[string]interface{}{
				"Error":    loginT["error_invalid"],
				"T":        trans,
				"Settings": settings,
			})
			return
		}
		// Reset anti-bruteforce counters after successful primary-factor auth.
		auth.ResetAttempts(r, database.Config.IsBehindProxy)
		needs2FA := user.TwoFAEnabled && user.TwoFASecret != ""
		Debugf("Successful login for user=%q (2fa_required=%t)", username, needs2FA)
		sessionID := auth.Store.Create(username, needs2FA)
		auth.SetSessionCookie(w, sessionID)
		if needs2FA {
			http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/", http.StatusSeeOther)
		}
		return
	}
	Templates.ExecuteTemplate(w, "login.html", map[string]interface{}{"T": trans, "Settings": settings})
}

/**
  Handle2FAVerify completes login for sessions waiting on TOTP verification.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func Handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	sessionID := auth.GetSessionCookie(r)
	if sessionID == "" || !auth.Store.Needs2FA(sessionID) {
		Debugf("2FA verify redirect (missing or completed 2FA session)")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	trans := T()
	twoFAT, _ := trans["twofa"].(map[string]interface{})
	settings := database.GetSettings()
	if r.Method == http.MethodPost {
		code := strings.TrimSpace(r.FormValue("code"))
		user := database.GetUser()
		secret := user.TwoFASecret
		if totp.Validate(code, secret) {
			// Successful 2FA - reset attempts
			auth.ResetAttempts(r, database.Config.IsBehindProxy)
			auth.Store.Complete2FA(sessionID)
			Debugf("2FA verification successful for user=%q", user.Username)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		// Keep error text generic while preserving localized copy when available.
		auth.RecordFailedAttempt(r, database.Config.IsBehindProxy)
		Debugf("2FA verification failed for user=%q", user.Username)
		errorInvalid := "Invalid verification code"
		if twoFAT != nil {
			if msg, ok := twoFAT["error_invalid"]; ok {
				if msgStr, ok := msg.(string); ok && msgStr != "" {
					errorInvalid = msgStr
				}
			}
		}
		Templates.ExecuteTemplate(w, "2fa_verify.html", map[string]interface{}{
			"Error":    errorInvalid,
			"T":        trans,
			"Settings": settings,
		})
		return
	}
	Templates.ExecuteTemplate(w, "2fa_verify.html", map[string]interface{}{"T": trans, "Settings": settings})
}

/**
  HandleResetPassword validates a backup code and rotates the password hash.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	// Check database connection first
	if !CheckDatabaseConnection(w, r) {
		return
	}
	if auth.RequireSetup(w, r) {
		return
	}
	trans := T()
	resetT := trans["reset"].(map[string]interface{})
	settings := database.GetSettings()
	if r.Method == http.MethodPost {
		backupCode := strings.ToUpper(strings.TrimSpace(r.FormValue("backup_code")))
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")
		user := database.GetUser()
		if user == nil {
			auth.RecordFailedAttempt(r, database.Config.IsBehindProxy)
			Templates.ExecuteTemplate(w, "reset_password.html", map[string]interface{}{
				"Error":    resetT["error_invalid_code"],
				"T":        trans,
				"Settings": settings,
			})
			return
		}
		// Validate backup code using constant-time comparison.
		if len(user.BackupCode) != len(backupCode) || subtle.ConstantTimeCompare([]byte(user.BackupCode), []byte(backupCode)) != 1 {
			auth.RecordFailedAttempt(r, database.Config.IsBehindProxy)
			Templates.ExecuteTemplate(w, "reset_password.html", map[string]interface{}{
				"Error":    resetT["error_invalid_code"],
				"T":        trans,
				"Settings": settings,
			})
			return
		}
		// Validate passwords match
		if newPassword != confirmPassword {
			Templates.ExecuteTemplate(w, "reset_password.html", map[string]interface{}{
				"Error":    resetT["error_mismatch"],
				"T":        trans,
				"Settings": settings,
			})
			return
		}
		// Validate password length
		if len(newPassword) < 6 {
			Templates.ExecuteTemplate(w, "reset_password.html", map[string]interface{}{
				"Error":    resetT["error_min_length"],
				"T":        trans,
				"Settings": settings,
			})
			return
		}
		// Generate new password hash
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			Templates.ExecuteTemplate(w, "reset_password.html", map[string]interface{}{
				"Error":    resetT["error_hash"],
				"T":        trans,
				"Settings": settings,
			})
			return
		}
		// Successful password reset - reset attempts
		auth.ResetAttempts(r, database.Config.IsBehindProxy)
		// Invalidate backup code after successful use to enforce one-time recovery.
		user.PasswordHash = string(hash)
		user.BackupCode = ""
		database.SetUser(user)
		// Show success message
		Templates.ExecuteTemplate(w, "reset_password.html", map[string]interface{}{
			"Success":  true,
			"T":        trans,
			"Settings": settings,
		})
		return
	}
	Templates.ExecuteTemplate(w, "reset_password.html", map[string]interface{}{
		"T":        trans,
		"Settings": settings,
	})
}

/**
  HandleLogout clears server-side and browser-side session state.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns void
*/
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := auth.GetSessionCookie(r)
	if sessionID != "" {
		auth.Store.Delete(sessionID)
	}
	auth.ClearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
