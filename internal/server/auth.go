package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"fileline/internal/auth"
	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/storage"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// Helper for random session identifiers
func generateRandomSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateRecoveryCode generates a human-readable recovery code (XXXX-XXXX-XXXX-XXXX) and its bcrypt hash
func generateRecoveryCode() (string, string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := strings.ToUpper(hex.EncodeToString(b))
	code := fmt.Sprintf("%s-%s-%s-%s", raw[0:4], raw[4:8], raw[8:12], raw[12:16])
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return code, string(hash), nil
}

// requireAuth is a middleware requiring an authenticated JWT session
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.isConfigured() {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		cookie, err := r.Cookie("session")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(s.cfg.JWTKey), nil
		})
		if err != nil || !token.Valid {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), "username", claims["username"])
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Server) setJWTCookie(w http.ResponseWriter, username string) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString([]byte(s.cfg.JWTKey))
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SSL || s.cfg.ReverseProxy,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 1 day
	})
}

func (s *Server) setupHandler(w http.ResponseWriter, r *http.Request) {
	if s.isConfigured() {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.mu.RLock()
	dbConfigured := s.db != nil
	s.mu.RUnlock()
	if r.Method == http.MethodGet {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title": "Setup", "Config": s.cfg,
			"DBConfigured": dbConfigured,
		})
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			s.renderSetupError(w, dbConfigured, "Invalid form submission")
			return
		}
		// Handle DB setup if not configured
		if !dbConfigured {
			dbType := r.FormValue("db_type")
			s.cfg.DBType = dbType
			switch dbType {
			case "sqlite":
				url := r.FormValue("sqlite_url")
				if url == "" {
					url = "data/database.sqlite"
				}
				s.cfg.SQLiteURL = url
			case "postgres":
				host := r.FormValue("pg_host")
				port := r.FormValue("pg_port")
				user := r.FormValue("pg_user")
				pass := r.FormValue("pg_password")
				dbname := r.FormValue("pg_db")
				s.cfg.PostgresURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, pass, host, port, dbname)
			default:
				s.renderSetupError(w, dbConfigured, "Invalid database type")
				return
			}
			// Try to connect
			database, err := db.InitDB(r.Context(), s.cfg)
			if err != nil {
				s.renderSetupError(w, dbConfigured, fmt.Sprintf("Database connection failed: %v", err))
				return
			}
			// Run migrations
			if err := db.Migrate(r.Context(), database, s.cfg.DBType); err != nil {
				database.Close()
				s.renderSetupError(w, dbConfigured, fmt.Sprintf("Migration failed: %v", err))
				return
			}
			s.mu.Lock()
			s.db = database
			s.mu.Unlock()
			// Save config
			s.cfg.Save("config.json")
			dbConfigured = true
		}

		// Always parse storage fields since they are always present on setup page
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
			s.cfg.S3SecretKey = r.FormValue("s3_secret_key")
			s.cfg.S3UseSSL = r.FormValue("s3_use_ssl") == "on"
		}
		s.cfg.Save("config.json") // Save config again with storage data

		s.mu.Lock()
		s.storage, _ = storage.NewProvider(r.Context(), s.cfg)
		s.mu.Unlock()

		// Handle Admin setup
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			s.renderSetupError(w, dbConfigured, "Username and password are required")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			s.renderSetupError(w, dbConfigured, "Failed to secure password")
			return
		}

		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()

		if err := db.CreateAdmin(r.Context(), database, username, string(hash)); err != nil {
			s.renderSetupError(w, dbConfigured, fmt.Sprintf("Failed to create admin: %v", err))
			return
		}
		if recoveryCode, recoveryHash, err := generateRecoveryCode(); err == nil {
			_ = db.UpdateRecoveryCode(r.Context(), database, username, recoveryHash)
			s.recoveryCodeStore.Store(username, recoveryCode)
		}
		logger.Action("Initial system setup completed (admin user: '%s')", username)
		// Login user automatically
		s.setJWTCookie(w, username)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	if !s.isConfigured() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if r.Method == http.MethodGet {
		s.renderTemplate(w, r, "login.html", map[string]interface{}{
			"Title":   "Login",
			"Config":  s.cfg,
			"Error":   r.URL.Query().Get("error"),
			"Success": r.URL.Query().Get("success"),
		})
		return
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()
		user, err := db.GetUserByUsername(r.Context(), database, username)
		if err != nil {
			logger.Action("Failed login attempt for username '%s' from %s (user not found)", username, s.clientIP(r))
			s.renderTemplate(w, r, "login.html", map[string]interface{}{
				"Title":  "Login",
				"Config": s.cfg,
				"Error":  "Invalid credentials",
			})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			logger.Action("Failed login attempt for username '%s' from %s (invalid password)", username, s.clientIP(r))
			s.renderTemplate(w, r, "login.html", map[string]interface{}{
				"Title":  "Login",
				"Config": s.cfg,
				"Error":  "Invalid credentials",
			})
			return
		}
		// Generate recovery code on first login if not yet generated (e.g. for subusers)
		if user.RecoveryCodeHash == "" {
			if recoveryCode, recoveryHash, err := generateRecoveryCode(); err == nil {
				if err := db.UpdateRecoveryCode(r.Context(), database, username, recoveryHash); err == nil {
					s.recoveryCodeStore.Store(username, recoveryCode)
					logger.Action("Generated initial recovery code for user '%s' on first login", username)
				}
			}
		}
		if user.TOTPSecret != "" {
			// Require 2FA
			sessionID := generateRandomSessionID()
			s.login2FAStore.Store(sessionID, username)
			http.SetCookie(w, &http.Cookie{
				Name:     "2fa_session",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				MaxAge:   300, // 5 minutes to complete
			})
			logger.Action("User '%s' authenticated with password, 2FA challenge required from %s", username, s.clientIP(r))
			http.Redirect(w, r, "/login/2fa", http.StatusFound)
			return
		}
		s.setJWTCookie(w, username)
		logger.Action("User '%s' logged in successfully via password from %s", username, s.clientIP(r))
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if !s.isConfigured() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if r.Method == http.MethodGet {
		s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
			"Title":  "Reset Password",
			"Config": s.cfg,
		})
		return
	}
	if r.Method == http.MethodPost {
		now := time.Now()
		s.resetMu.Lock()
		if !s.resetBlockedUntil.IsZero() {
			if now.Before(s.resetBlockedUntil) {
				s.resetMu.Unlock()
				logger.Action("Blocked password reset attempt from %s (rate limit active)", s.clientIP(r))
				w.WriteHeader(http.StatusTooManyRequests)
				s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
					"Title":  "Reset Password",
					"Config": s.cfg,
					"Error":  "Too many failed attempts. Try again in 1 hour.",
				})
				return
			}
			s.resetBlockedUntil = time.Time{}
			s.resetAttempts = 0
		}
		s.resetMu.Unlock()

		username := strings.TrimSpace(r.FormValue("username"))
		recoveryCode := strings.TrimSpace(r.FormValue("recovery_code"))
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()

		user, err := db.GetUserByUsername(r.Context(), database, username)
		invalidCreds := username == "" || recoveryCode == "" || err != nil || user.RecoveryCodeHash == "" ||
			bcrypt.CompareHashAndPassword([]byte(user.RecoveryCodeHash), []byte(recoveryCode)) != nil

		if invalidCreds {
			s.resetMu.Lock()
			s.resetAttempts++
			attempts := s.resetAttempts
			if attempts >= 3 {
				s.resetBlockedUntil = time.Now().Add(time.Hour)
			}
			s.resetMu.Unlock()

			if attempts >= 3 {
				logger.Action("Failed password reset attempt for username '%s' from %s (rate limit reached: %d/3, locked for 1h)", username, s.clientIP(r), attempts)
				w.WriteHeader(http.StatusTooManyRequests)
				s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
					"Title":  "Reset Password",
					"Config": s.cfg,
					"Error":  "Too many failed attempts. Try again in 1 hour.",
				})
				return
			}
			logger.Action("Failed password reset attempt for username '%s' from %s (attempt %d/3)", username, s.clientIP(r), attempts)
			s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
				"Title":  "Reset Password",
				"Config": s.cfg,
				"Error":  "Invalid username or recovery code",
			})
			return
		}

		if newPassword == "" {
			s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
				"Title":  "Reset Password",
				"Config": s.cfg,
				"Error":  "Username and password are required",
			})
			return
		}

		if newPassword != confirmPassword {
			s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
				"Title":  "Reset Password",
				"Config": s.cfg,
				"Error":  "Passwords do not match",
			})
			return
		}

		newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			s.internalError(w, r, "Failed to hash new password during recovery", err)
			return
		}

		if err := db.UpdatePassword(r.Context(), database, username, string(newHash)); err != nil {
			s.internalError(w, r, "Failed to update password during recovery", err)
			return
		}

		s.resetMu.Lock()
		s.resetAttempts = 0
		s.resetBlockedUntil = time.Time{}
		s.resetMu.Unlock()

		logger.Action("User '%s' successfully reset their password using recovery code from %s", username, s.clientIP(r))
		http.Redirect(w, r, "/login?success=Password+updated+successfully", http.StatusFound)
	}
}

func (s *Server) login2FAHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("2fa_session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	sessionID := cookie.Value
	usernameAny, ok := s.login2FAStore.Load(sessionID)
	if !ok {
		http.Redirect(w, r, "/login?error=Session+expired", http.StatusFound)
		return
	}
	username := usernameAny.(string)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.TOTPSecret == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		s.renderTemplate(w, r, "login_2fa.html", map[string]interface{}{
			"Title":      "Two-Factor Authentication",
			"Config":     s.cfg,
			"User":       user,
			"TargetUser": username,
		})
		return
	}

	if r.Method == http.MethodPost {
		code := strings.TrimSpace(r.FormValue("code"))
		if !totp.Validate(code, user.TOTPSecret) {
			logger.Action("User '%s' failed 2FA verification from %s", username, s.clientIP(r))
			s.renderTemplate(w, r, "login_2fa.html", map[string]interface{}{
				"Title":      "Two-Factor Authentication",
				"Config":     s.cfg,
				"User":       user,
				"TargetUser": username,
				"Error":      "Invalid verification code",
			})
			return
		}
		// Success
		s.login2FAStore.Delete(sessionID)
		http.SetCookie(w, &http.Cookie{
			Name:     "2fa_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
		})
		s.setJWTCookie(w, username)
		logger.Action("User '%s' logged in successfully via 2FA TOTP from %s", username, s.clientIP(r))
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	username := ""
	if cookie, err := r.Cookie("session"); err == nil && cookie.Value != "" {
		token, _ := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			s.mu.RLock()
			key := []byte(s.cfg.JWTKey)
			s.mu.RUnlock()
			return key, nil
		})
		if token != nil && token.Valid {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if u, ok := claims["username"].(string); ok {
					username = u
				}
			}
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	if username != "" {
		logger.Action("User '%s' logged out", username)
	} else {
		logger.Action("User logged out (session cleared)")
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) webAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, sessionData, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		s.internalError(w, r, "WebAuthn BeginDiscoverableLogin failed", err)
		return
	}

	sessionID := generateRandomSessionID()
	s.webAuthnTempStore.Store(sessionID, *sessionData)
	http.SetCookie(w, &http.Cookie{
		Name:     "wa_login_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (s *Server) webAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("wa_login_session")
	if err != nil {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}
	sessionID := cookie.Value
	sessionDataAny, ok := s.webAuthnTempStore.Load(sessionID)
	if !ok {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}
	sessionData := sessionDataAny.(webauthn.SessionData)
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	var loggedInUsername string
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		idStr := string(userHandle)
		var id int
		if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
			return nil, fmt.Errorf("invalid user handle")
		}
		dbUser, err := db.GetUserByID(r.Context(), database, id)
		if err != nil {
			return nil, err
		}
		loggedInUsername = dbUser.Username
		return auth.NewWebAuthnUser(dbUser), nil
	}
	_, err = s.webAuthn.FinishDiscoverableLogin(handler, sessionData, r)
	if err != nil {
		logger.Action("Failed Passkey login attempt from %s: %v", s.clientIP(r), err)
		http.Error(w, "Invalid passkey authentication", http.StatusBadRequest)
		return
	}
	s.webAuthnTempStore.Delete(sessionID)
	s.setJWTCookie(w, loggedInUsername)
	logger.Action("User '%s' logged in successfully via Passkey (WebAuthn) from %s", loggedInUsername, s.clientIP(r))
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok", "redirect":"/"}`))
}
