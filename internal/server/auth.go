package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"fileline/internal/auth"
	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/storage"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
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

const jwtIssuer = "fileline"

type sessionClaims struct {
	Username string `json:"username"`
	Ver      *int   `json:"ver,omitempty"`
	jwt.RegisteredClaims
}

// parseSessionClaims verifies a session JWT using strict HS256 options and returns the parsed claims.
// It refuses to validate tokens if the server's JWT key is invalid.
func (s *Server) parseSessionClaims(tokenStr string) (*sessionClaims, bool) {
	if tokenStr == "" {
		return nil, false
	}
	s.mu.RLock()
	var key string
	if s.cfg != nil {
		key = s.cfg.JWTKey
	}
	s.mu.RUnlock()
	if !config.IsValidJWTKey(key) {
		return nil, false
	}

	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	}

	claims := &sessionClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(key), nil
	}, parserOpts...)
	if err != nil || token == nil || !token.Valid {
		return nil, false
	}
	// If issuer is present on the token, require it to match "fileline"; tokens minted by writeSessionCookie always set iss="fileline".
	if claims.Issuer != "" && claims.Issuer != jwtIssuer {
		return nil, false
	}
	if claims.Username == "" {
		return nil, false
	}
	return claims, true
}

// parseJWTUsername verifies a session JWT using HS256 and returns the username claim.
// When a database is configured, it also verifies that the user still exists and that the token's session version matches.
func (s *Server) parseJWTUsername(tokenStr string) (string, bool) {
	claims, ok := s.parseSessionClaims(tokenStr)
	if !ok {
		return "", false
	}
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	if database != nil {
		user, err := db.GetUserByUsername(context.Background(), database, claims.Username)
		if err != nil || user == nil {
			return "", false
		}
		tokenVer := 0
		if claims.Ver != nil {
			tokenVer = *claims.Ver
		}
		if tokenVer != user.SessionVersion {
			return "", false
		}
	}
	return claims.Username, true
}

// parseSession verifies the session cookie from r, loads the user from the database,
// and checks that the user still exists and the token's session version (`ver`) matches `user.SessionVersion`.
func (s *Server) parseSession(r *http.Request) (*db.User, bool) {
	if r == nil {
		return nil, false
	}
	cookie, err := r.Cookie("session")
	if err != nil || cookie.Value == "" {
		return nil, false
	}
	claims, ok := s.parseSessionClaims(cookie.Value)
	if !ok {
		return nil, false
	}
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	if database == nil {
		return nil, false
	}
	user, err := db.GetUserByUsername(r.Context(), database, claims.Username)
	if err != nil || user == nil {
		return nil, false
	}
	tokenVer := 0
	if claims.Ver != nil {
		tokenVer = *claims.Ver
	}
	if tokenVer != user.SessionVersion {
		return nil, false
	}
	return user, true
}

// requireAuth is a middleware requiring an authenticated, non-revoked JWT session for an existing user
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		configured, err := s.CheckConfigured(r.Context())
		if err != nil {
			logger.Error("Database error checking configuration state: %v", err)
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}
		if !configured {
			http.Redirect(w, r, "/setup", http.StatusFound)
			return
		}
		user, ok := s.parseSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), "username", user.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (s *Server) setJWTCookie(w http.ResponseWriter, username string) {
	s.mu.RLock()
	if !config.IsValidJWTKey(s.cfg.JWTKey) {
		s.mu.RUnlock()
		s.mu.Lock()
		if !config.IsValidJWTKey(s.cfg.JWTKey) {
			_ = s.cfg.EnsureJWTKey("config.json")
		}
		key := s.cfg.JWTKey
		secure := s.cfg.SSL || s.cfg.ReverseProxy
		database := s.db
		s.mu.Unlock()
		ver := 0
		if database != nil {
			if u, err := db.GetUserByUsername(context.Background(), database, username); err == nil && u != nil {
				ver = u.SessionVersion
			}
		}
		s.writeSessionCookie(w, username, ver, key, secure)
		return
	}
	key := s.cfg.JWTKey
	secure := s.cfg.SSL || s.cfg.ReverseProxy
	database := s.db
	s.mu.RUnlock()
	ver := 0
	if database != nil {
		if u, err := db.GetUserByUsername(context.Background(), database, username); err == nil && u != nil {
			ver = u.SessionVersion
		}
	}
	s.writeSessionCookie(w, username, ver, key, secure)
}

func (s *Server) writeSessionCookie(w http.ResponseWriter, username string, sessionVersion int, key string, secure bool) {
	now := time.Now()
	claims := sessionClaims{
		Username: username,
		Ver:      &sessionVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Subject:   username,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(key))
	if err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400, // 1 day
	})
}

// containsParentSegment reports whether raw contains any ".." path component before cleaning
func containsParentSegment(raw string) bool {
	return slices.Contains(strings.Split(strings.ReplaceAll(raw, "\\", "/"), "/"), "..")
}

// isDisallowedSystemPath reports whether a cleaned absolute path points into OS system directories
func isDisallowedSystemPath(clean string) bool {
	slashed := filepath.ToSlash(clean)
	if !strings.HasPrefix(slashed, "/") {
		return false
	}
	for _, prefix := range []string{
		"/etc", "/bin", "/sbin", "/usr", "/lib", "/lib64",
		"/proc", "/sys", "/dev", "/boot", "/root", "/var/run", "/run/systemd",
	} {
		if slashed == prefix || strings.HasPrefix(slashed, prefix+"/") {
			return true
		}
	}
	return false
}

// validateSetupSQLitePath rejects parent-directory traversal and absolute paths outside /app/data.
func validateSetupSQLitePath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "data/database.sqlite", nil
	}
	if p == ":memory:" {
		return p, nil
	}
	if strings.ContainsAny(p, "\x00\r\n") || containsParentSegment(p) {
		return "", errors.New("invalid database path")
	}
	clean := filepath.Clean(filepath.FromSlash(p))
	if clean == "." || clean == "/" || clean == "\\" || isDisallowedSystemPath(clean) {
		return "", errors.New("invalid database path")
	}
	if filepath.IsAbs(clean) && !strings.HasPrefix(filepath.ToSlash(clean), "/app/data/") {
		return "", errors.New("database path must be relative to the application directory")
	}
	return clean, nil
}

// validateSetupLocalPath rejects root/system paths and parent-directory traversal in setup
func validateSetupLocalPath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "./uploads", nil
	}
	if strings.ContainsAny(p, "\x00\r\n") || containsParentSegment(p) {
		return "", errors.New("invalid storage path")
	}
	clean := filepath.Clean(filepath.FromSlash(p))
	if clean == "/" || clean == "\\" || clean == "." || clean == ".." || isDisallowedSystemPath(clean) {
		return "", errors.New("invalid storage path")
	}
	return clean, nil
}

func (s *Server) setupHandler(w http.ResponseWriter, r *http.Request) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()

	configured, err := s.CheckConfigured(r.Context())
	if err != nil {
		logger.Error("Database error checking setup state: %v", err)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if configured {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	s.mu.RLock()
	dbConfigured := s.db != nil
	cfgCopy := *s.cfg
	s.mu.RUnlock()
	requireToken := s.setupToken != ""

	if r.Method == http.MethodGet {
		s.renderTemplate(w, r, "setup.html", map[string]interface{}{
			"Title":        "Setup",
			"Config":       &cfgCopy,
			"DBConfigured": dbConfigured,
			"RequireToken": requireToken,
			"SetupToken":   r.URL.Query().Get("token"),
		})
		return
	}

	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
		if err := r.ParseForm(); err != nil {
			if isMaxBytesError(err) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			s.renderSetupError(w, dbConfigured, "Invalid form submission")
			return
		}

		// Verify one-time setup token when enabled (constant-time comparison)
		if requireToken {
			supplied := strings.TrimSpace(r.FormValue("setup_token"))
			if supplied == "" {
				supplied = strings.TrimSpace(r.URL.Query().Get("token"))
			}
			if subtle.ConstantTimeCompare([]byte(supplied), []byte(s.setupToken)) != 1 {
				logger.Action("Rejected setup attempt from %s: invalid setup token", s.clientIP(r))
				w.WriteHeader(http.StatusForbidden)
				s.renderSetupError(w, dbConfigured, "Invalid setup token")
				return
			}
		}

		// Handle DB setup if not configured
		if !dbConfigured {
			dbType := r.FormValue("db_type")
			candidateCfg := cfgCopy
			candidateCfg.DBType = dbType
			switch dbType {
			case "sqlite":
				sqlitePath, pathErr := validateSetupSQLitePath(r.FormValue("sqlite_url"))
				if pathErr != nil {
					s.renderSetupError(w, dbConfigured, "Invalid database configuration")
					return
				}
				candidateCfg.SQLiteURL = sqlitePath
			case "postgres":
				host := strings.TrimSpace(r.FormValue("pg_host"))
				port := strings.TrimSpace(r.FormValue("pg_port"))
				user := strings.TrimSpace(r.FormValue("pg_user"))
				pass := r.FormValue("pg_password")
				dbname := strings.TrimSpace(r.FormValue("pg_db"))
				if host == "" || dbname == "" {
					s.renderSetupError(w, dbConfigured, "Invalid database configuration")
					return
				}
				hostPort := host
				if port != "" {
					hostPort = net.JoinHostPort(host, port)
				}
				sslMode := strings.TrimSpace(r.FormValue("pg_sslmode"))
				switch sslMode {
				case "":
					sslMode = "require"
				case "require", "verify-full", "verify-ca", "disable":
				default:
					s.renderSetupError(w, dbConfigured, "Invalid database configuration")
					return
				}
				query := url.Values{}
				query.Set("sslmode", sslMode)
				pgURL := url.URL{
					Scheme:   "postgres",
					User:     url.UserPassword(user, pass),
					Host:     hostPort,
					Path:     "/" + strings.TrimPrefix(dbname, "/"),
					RawQuery: query.Encode(),
				}
				candidateCfg.PostgresURL = pgURL.String()
			default:
				s.renderSetupError(w, dbConfigured, "Invalid database type")
				return
			}
			// Try to connect
			database, err := db.InitDB(r.Context(), &candidateCfg)
			if err != nil {
				logger.Error("Setup database connection failed: %v", err)
				s.renderSetupError(w, dbConfigured, "Database connection failed")
				return
			}
			// Run migrations
			if err := db.Migrate(r.Context(), database, candidateCfg.DBType); err != nil {
				database.Close()
				logger.Error("Setup database migration failed: %v", err)
				s.renderSetupError(w, dbConfigured, "Database migration failed")
				return
			}
			// Check whether the newly connected DB already has an admin account
			hasAdmin, err := db.HasAdmin(r.Context(), database)
			if err != nil {
				database.Close()
				logger.Error("Setup HasAdmin check failed: %v", err)
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}
			s.mu.Lock()
			s.cfg.DBType = candidateCfg.DBType
			s.cfg.SQLiteURL = candidateCfg.SQLiteURL
			s.cfg.PostgresURL = candidateCfg.PostgresURL
			s.db = database
			if saveErr := s.cfg.Save("config.json"); saveErr != nil {
				logger.Error("Failed to save config during setup: %v", saveErr)
			}
			s.mu.Unlock()
			dbConfigured = true
			if hasAdmin {
				s.configured.Store(true)
				s.setupToken = ""
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
		}

		// Parse and validate storage fields
		storageType := r.FormValue("storage_type")
		var localPath string
		switch storageType {
		case "local", "":
			storageType = "local"
			var pathErr error
			localPath, pathErr = validateSetupLocalPath(r.FormValue("local_path"))
			if pathErr != nil {
				s.renderSetupError(w, dbConfigured, "Invalid storage path")
				return
			}
		case "s3":
		default:
			s.renderSetupError(w, dbConfigured, "Invalid storage type")
			return
		}

		// Validate Admin credentials before mutating storage config
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		if username == "" || password == "" {
			s.renderSetupError(w, dbConfigured, "Username and password are required")
			return
		}
		if err := validateUsername(username); err != nil {
			s.renderSetupError(w, dbConfigured, err.Error())
			return
		}
		if err := validatePassword(password); err != nil {
			s.renderSetupError(w, dbConfigured, err.Error())
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			s.renderSetupError(w, dbConfigured, "Failed to secure password")
			return
		}

		s.mu.Lock()
		s.cfg.StorageType = storageType
		if storageType == "local" {
			s.cfg.LocalStoragePath = localPath
		} else {
			s.cfg.S3Endpoint = r.FormValue("s3_endpoint")
			s.cfg.S3Region = r.FormValue("s3_region")
			s.cfg.S3Bucket = r.FormValue("s3_bucket")
			s.cfg.S3AccessKey = r.FormValue("s3_access_key")
			s.cfg.S3SecretKey = r.FormValue("s3_secret_key")
			s.cfg.S3UseSSL = r.FormValue("s3_use_ssl") == "on"
		}
		if err := s.cfg.EnsureJWTKey("config.json"); err != nil {
			logger.Error("Failed to ensure JWT key during setup: %v", err)
		} else if err := s.cfg.Save("config.json"); err != nil {
			logger.Error("Failed to save config during setup: %v", err)
		}
		st, stErr := storage.NewProvider(r.Context(), s.cfg)
		if stErr != nil {
			logger.Error("Failed to initialize storage provider during setup: %v", stErr)
		} else {
			s.storage = st
		}
		database := s.db
		s.mu.Unlock()

		if err := db.CreateAdmin(r.Context(), database, username, string(hash)); err != nil {
			if errors.Is(err, db.ErrAdminAlreadyExists) {
				s.configured.Store(true)
				s.setupToken = ""
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			logger.Error("Setup failed to create admin '%s': %v", username, err)
			s.renderSetupError(w, dbConfigured, "Failed to create admin account")
			return
		}

		s.configured.Store(true)
		s.setupToken = ""

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
	configured, err := s.CheckConfigured(r.Context())
	if err != nil {
		logger.Error("Database error checking configuration state: %v", err)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if !configured {
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
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
		if err := r.ParseForm(); err != nil {
			if isMaxBytesError(err) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Invalid form submission", http.StatusBadRequest)
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		password := r.FormValue("password")
		now := time.Now()
		clientIP := s.clientIP(r)
		lim := s.limiter()
		userKey := authRateKey("login", clientIP, username)
		ipKey := authRateKey("login-ip", clientIP, "*")

		if blocked, retry := lim.check(userKey, now); blocked {
			setRetryAfterHeader(w, retry)
			w.WriteHeader(http.StatusTooManyRequests)
			s.renderTemplate(w, r, "login.html", map[string]interface{}{
				"Title":  "Login",
				"Config": s.cfg,
				"Error":  "Too many failed login attempts. Please try again later.",
			})
			return
		}
		if blocked, retry := lim.check(ipKey, now); blocked {
			setRetryAfterHeader(w, retry)
			w.WriteHeader(http.StatusTooManyRequests)
			s.renderTemplate(w, r, "login.html", map[string]interface{}{
				"Title":  "Login",
				"Config": s.cfg,
				"Error":  "Too many failed login attempts. Please try again later.",
			})
			return
		}

		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()
		user, err := db.GetUserByUsername(r.Context(), database, username)
		if err != nil {
			// Run a dummy bcrypt comparison so response timing does not reveal whether the username exists.
			_ = bcrypt.CompareHashAndPassword(getDummyPasswordHash(), []byte(password))
			_, blockedUser, retryUser := lim.recordFailure(userKey, now, loginMaxAttempts, loginWindow, loginWindow)
			_, blockedIP, retryIP := lim.recordFailure(ipKey, now, loginMaxAttempts*2, loginWindow, loginWindow)
			if blockedUser || blockedIP {
				retry := retryUser
				if retryIP > retry {
					retry = retryIP
				}
				logger.Info("Rate limit lockout on /login for username '%s' from %s", username, clientIP)
				setRetryAfterHeader(w, retry)
				w.WriteHeader(http.StatusTooManyRequests)
				s.renderTemplate(w, r, "login.html", map[string]interface{}{
					"Title":  "Login",
					"Config": s.cfg,
					"Error":  "Too many failed login attempts. Please try again later.",
				})
				return
			}
			logger.Action("Failed login attempt for username '%s' from %s (user not found)", username, clientIP)
			s.renderTemplate(w, r, "login.html", map[string]interface{}{
				"Title":  "Login",
				"Config": s.cfg,
				"Error":  "Invalid credentials",
			})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			_, blockedUser, retryUser := lim.recordFailure(userKey, now, loginMaxAttempts, loginWindow, loginWindow)
			_, blockedIP, retryIP := lim.recordFailure(ipKey, now, loginMaxAttempts*2, loginWindow, loginWindow)
			if blockedUser || blockedIP {
				retry := retryUser
				if retryIP > retry {
					retry = retryIP
				}
				logger.Info("Rate limit lockout on /login for username '%s' from %s", username, clientIP)
				setRetryAfterHeader(w, retry)
				w.WriteHeader(http.StatusTooManyRequests)
				s.renderTemplate(w, r, "login.html", map[string]interface{}{
					"Title":  "Login",
					"Config": s.cfg,
					"Error":  "Too many failed login attempts. Please try again later.",
				})
				return
			}
			logger.Action("Failed login attempt for username '%s' from %s (invalid password)", username, clientIP)
			s.renderTemplate(w, r, "login.html", map[string]interface{}{
				"Title":  "Login",
				"Config": s.cfg,
				"Error":  "Invalid credentials",
			})
			return
		}

		lim.reset(userKey)
		lim.reset(ipKey)

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
			// Require 2FA with server-side expiry and attempt cap
			sessionID := generateRandomSessionID()
			s.login2FAStore.Store(sessionID, &twoFASession{
				Username:  username,
				ExpiresAt: now.Add(twoFASessionTTL),
			})
			http.SetCookie(w, &http.Cookie{
				Name:     "2fa_session",
				Value:    sessionID,
				Path:     "/",
				HttpOnly: true,
				Secure:   s.cfg.SSL || s.cfg.ReverseProxy,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   int(twoFASessionTTL.Seconds()),
			})
			logger.Action("User '%s' authenticated with password, 2FA challenge required from %s", username, clientIP)
			http.Redirect(w, r, "/login/2fa", http.StatusFound)
			return
		}
		s.setJWTCookie(w, username)
		logger.Action("User '%s' logged in successfully via password from %s", username, clientIP)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	configured, err := s.CheckConfigured(r.Context())
	if err != nil {
		logger.Error("Database error checking configuration state: %v", err)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return
	}
	if !configured {
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
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
		if err := r.ParseForm(); err != nil {
			if isMaxBytesError(err) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Invalid form submission", http.StatusBadRequest)
			return
		}
		now := time.Now()
		username := strings.TrimSpace(r.FormValue("username"))
		recoveryCode := strings.TrimSpace(r.FormValue("recovery_code"))
		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		clientIP := s.clientIP(r)
		lim := s.limiter()
		// Rate limit per-(IP, username) and per-IP so an attacker on one IP cannot lock out other users globally.
		userKey := authRateKey("reset", clientIP, username)
		ipKey := authRateKey("reset-ip", clientIP, "*")

		if blocked, retry := lim.check(userKey, now); blocked {
			logger.Info("Blocked password reset attempt for '%s' from %s (rate limit active)", username, clientIP)
			setRetryAfterHeader(w, retry)
			w.WriteHeader(http.StatusTooManyRequests)
			s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
				"Title":  "Reset Password",
				"Config": s.cfg,
				"Error":  "Too many failed attempts. Try again in 1 hour.",
			})
			return
		}
		if blocked, retry := lim.check(ipKey, now); blocked {
			logger.Info("Blocked password reset attempt from %s (IP rate limit active)", clientIP)
			setRetryAfterHeader(w, retry)
			w.WriteHeader(http.StatusTooManyRequests)
			s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
				"Title":  "Reset Password",
				"Config": s.cfg,
				"Error":  "Too many failed attempts. Try again in 1 hour.",
			})
			return
		}

		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()

		user, err := db.GetUserByUsername(r.Context(), database, username)
		var invalidCreds bool
		if username == "" || recoveryCode == "" || err != nil || user.RecoveryCodeHash == "" {
			_ = bcrypt.CompareHashAndPassword(getDummyPasswordHash(), []byte(recoveryCode))
			invalidCreds = true
		} else if bcrypt.CompareHashAndPassword([]byte(user.RecoveryCodeHash), []byte(recoveryCode)) != nil {
			invalidCreds = true
		}

		if invalidCreds {
			attempts, blockedUser, retryUser := lim.recordFailure(userKey, now, resetMaxAttempts, resetLockoutDuration, resetLockoutDuration)
			ipAttempts, blockedIP, retryIP := lim.recordFailure(ipKey, now, resetMaxAttempts, resetLockoutDuration, resetLockoutDuration)
			if ipAttempts > attempts {
				attempts = ipAttempts
			}

			if blockedUser || blockedIP {
				retry := retryUser
				if retryIP > retry {
					retry = retryIP
				}
				logger.Info("Failed password reset attempt for username '%s' from %s (rate limit reached: %d/%d, locked for 1h)", username, clientIP, attempts, resetMaxAttempts)
				setRetryAfterHeader(w, retry)
				w.WriteHeader(http.StatusTooManyRequests)
				s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
					"Title":  "Reset Password",
					"Config": s.cfg,
					"Error":  "Too many failed attempts. Try again in 1 hour.",
				})
				return
			}
			logger.Action("Failed password reset attempt for username '%s' from %s (attempt %d/%d)", username, clientIP, attempts, resetMaxAttempts)
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
		if err := validatePassword(newPassword); err != nil {
			s.renderTemplate(w, r, "reset_password.html", map[string]interface{}{
				"Title":  "Reset Password",
				"Config": s.cfg,
				"Error":  err.Error(),
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

		newRecoveryCode, newRecoveryHash, err := generateRecoveryCode()
		if err != nil {
			s.internalError(w, r, "Failed to generate new recovery code during password reset", err)
			return
		}

		if err := db.ResetPasswordWithRecoveryRotation(r.Context(), database, username, string(newHash), newRecoveryHash); err != nil {
			s.internalError(w, r, "Failed to update password during recovery", err)
			return
		}

		s.recoveryCodeStore.Store(username, newRecoveryCode)
		lim.reset(userKey)
		lim.reset(ipKey)

		logger.Action("User '%s' successfully reset their password using recovery code from %s (recovery code rotated)", username, clientIP)
		http.Redirect(w, r, "/login?success=Password+updated+successfully", http.StatusFound)
	}
}

// load2FASession retrieves and validates a 2FA session, upgrading any plain string entry
func (s *Server) load2FASession(sessionID string, now time.Time) (*twoFASession, bool) {
	s.login2FAMu.Lock()
	defer s.login2FAMu.Unlock()

	raw, ok := s.login2FAStore.Load(sessionID)
	if !ok {
		return nil, false
	}
	switch v := raw.(type) {
	case *twoFASession:
		if now.After(v.ExpiresAt) || v.Attempts >= twoFAMaxAttempts {
			s.login2FAStore.Delete(sessionID)
			return nil, false
		}
		return v, true
	case string:
		sess := &twoFASession{
			Username:  v,
			ExpiresAt: now.Add(twoFASessionTTL),
		}
		s.login2FAStore.Store(sessionID, sess)
		return sess, true
	default:
		s.login2FAStore.Delete(sessionID)
		return nil, false
	}
}

func (s *Server) record2FAFailure(sessionID string) (remaining int, exhausted bool) {
	s.login2FAMu.Lock()
	defer s.login2FAMu.Unlock()

	raw, ok := s.login2FAStore.Load(sessionID)
	if !ok {
		return 0, true
	}
	sess, ok := raw.(*twoFASession)
	if !ok {
		s.login2FAStore.Delete(sessionID)
		return 0, true
	}
	sess.Attempts++
	if sess.Attempts >= twoFAMaxAttempts {
		s.login2FAStore.Delete(sessionID)
		return 0, true
	}
	return twoFAMaxAttempts - sess.Attempts, false
}

func (s *Server) login2FAHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("2fa_session")
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	now := time.Now()
	sessionID := cookie.Value
	sess, ok := s.load2FASession(sessionID, now)
	if !ok {
		http.Redirect(w, r, "/login?error=Session+expired", http.StatusFound)
		return
	}
	username := sess.Username

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
		r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
		if err := r.ParseForm(); err != nil {
			if isMaxBytesError(err) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "Invalid form submission", http.StatusBadRequest)
			return
		}
		clientIP := s.clientIP(r)
		lim := s.limiter()
		rateKey := authRateKey("2fa", clientIP, username)
		if blocked, retry := lim.check(rateKey, now); blocked {
			setRetryAfterHeader(w, retry)
			w.WriteHeader(http.StatusTooManyRequests)
			s.renderTemplate(w, r, "login_2fa.html", map[string]interface{}{
				"Title":      "Two-Factor Authentication",
				"Config":     s.cfg,
				"User":       user,
				"TargetUser": username,
				"Error":      "Too many failed verification attempts. Please try again later.",
			})
			return
		}

		code := strings.TrimSpace(r.FormValue("code"))
		step, valid := matchTOTPStep(code, user.TOTPSecret, now)
		if valid {
			consumed, dbErr := db.TryConsumeTOTPStep(r.Context(), database, username, step)
			if dbErr != nil || !consumed {
				// Replay of an already-used TOTP code within its window is rejected
				valid = false
			}
		}

		if !valid {
			_, exhausted := s.record2FAFailure(sessionID)
			_, blocked, retry := lim.recordFailure(rateKey, now, loginMaxAttempts, loginWindow, loginWindow)
			logger.Action("User '%s' failed 2FA verification from %s", username, clientIP)
			if blocked {
				logger.Info("Rate limit lockout on /login/2fa for username '%s' from %s", username, clientIP)
				setRetryAfterHeader(w, retry)
				w.WriteHeader(http.StatusTooManyRequests)
				s.renderTemplate(w, r, "login_2fa.html", map[string]interface{}{
					"Title":      "Two-Factor Authentication",
					"Config":     s.cfg,
					"User":       user,
					"TargetUser": username,
					"Error":      "Too many failed verification attempts. Please try again later.",
				})
				return
			}
			if exhausted {
				logger.Info("2FA session exhausted after %d failed attempts for username '%s' from %s", twoFAMaxAttempts, username, clientIP)
				s.mu.RLock()
				secure := s.cfg != nil && (s.cfg.SSL || s.cfg.ReverseProxy)
				s.mu.RUnlock()
				http.SetCookie(w, &http.Cookie{
					Name:     "2fa_session",
					Value:    "",
					Path:     "/",
					MaxAge:   -1,
					HttpOnly: true,
					Secure:   secure,
					SameSite: http.SameSiteStrictMode,
				})
				http.Redirect(w, r, "/login?error=Too+many+failed+2FA+attempts", http.StatusFound)
				return
			}
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
		lim.reset(rateKey)
		s.login2FAStore.Delete(sessionID)
		s.mu.RLock()
		secure := s.cfg != nil && (s.cfg.SSL || s.cfg.ReverseProxy)
		s.mu.RUnlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "2fa_session",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		})
		s.setJWTCookie(w, username)
		logger.Action("User '%s' logged in successfully via 2FA TOTP from %s", username, clientIP)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	username := ""
	if user, ok := s.parseSession(r); ok && user != nil {
		username = user.Username
		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()
		if database != nil {
			_ = db.IncrementSessionVersion(r.Context(), database, username)
		}
	}
	s.mu.RLock()
	secure := s.cfg != nil && (s.cfg.SSL || s.cfg.ReverseProxy)
	s.mu.RUnlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	if username != "" {
		logger.Action("User '%s' logged out", username)
	} else {
		logger.Action("User logged out (session cleared)")
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) webAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	clientIP := s.clientIP(r)
	lim := s.limiter()
	beginKey := authRateKey("webauthn-login-begin", clientIP, "*")
	if _, blocked, retry := lim.recordFailure(beginKey, now, loginMaxAttempts*2, loginWindow, loginWindow); blocked {
		setRetryAfterHeader(w, retry)
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	options, sessionData, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		s.internalError(w, r, "WebAuthn BeginDiscoverableLogin failed", err)
		return
	}

	sessionID := generateRandomSessionID()
	s.webAuthnTempStore.Store(sessionID, *sessionData)
	s.mu.RLock()
	secure := s.cfg != nil && (s.cfg.SSL || s.cfg.ReverseProxy)
	s.mu.RUnlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "wa_login_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   300,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// updateUserPasskeyCredential updates the matching passkey credential (SignCount, Flags, CloneWarning) in the user's stored WebAuthnData
func updateUserPasskeyCredential(ctx context.Context, database *sql.DB, dbUser *db.User, cred *webauthn.Credential) error {
	if database == nil || dbUser == nil || cred == nil {
		return nil
	}
	var passkeys []auth.Passkey
	if dbUser.WebAuthnData != "" {
		if err := json.Unmarshal([]byte(dbUser.WebAuthnData), &passkeys); err != nil {
			return err
		}
	}
	updated := false
	for i := range passkeys {
		if string(passkeys[i].Credential.ID) == string(cred.ID) {
			passkeys[i].Credential = *cred
			updated = true
			break
		}
	}
	if !updated {
		return fmt.Errorf("passkey credential not found for user")
	}
	credsJSON, err := json.Marshal(passkeys)
	if err != nil {
		return err
	}
	return db.UpdateUserAuthData(ctx, database, dbUser.Username, dbUser.TOTPSecret, string(credsJSON))
}

func (s *Server) webAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONOrFormBodyBytes)
	now := time.Now()
	clientIP := s.clientIP(r)
	lim := s.limiter()
	waKey := authRateKey("webauthn-login", clientIP, "*")
	if blocked, retry := lim.check(waKey, now); blocked {
		setRetryAfterHeader(w, retry)
		http.Error(w, "Too many failed attempts", http.StatusTooManyRequests)
		return
	}

	cookie, err := r.Cookie("wa_login_session")
	if err != nil {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}
	sessionID := cookie.Value
	sessionData, ok := s.webAuthnTempStore.LoadAndDelete(sessionID)
	if !ok {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	var loggedInUser *db.User
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
		loggedInUser = dbUser
		return auth.NewWebAuthnUser(dbUser), nil
	}
	credential, err := s.webAuthn.FinishDiscoverableLogin(handler, sessionData, r)
	if err != nil {
		if isMaxBytesError(err) {
			http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		if _, blocked, retry := lim.recordFailure(waKey, now, loginMaxAttempts, loginWindow, loginWindow); blocked {
			setRetryAfterHeader(w, retry)
			http.Error(w, "Too many failed attempts", http.StatusTooManyRequests)
			return
		}
		logger.Action("Failed Passkey login attempt from %s: %v", clientIP, err)
		http.Error(w, "Invalid passkey authentication", http.StatusBadRequest)
		return
	}
	if credential != nil && credential.Authenticator.CloneWarning {
		if loggedInUser != nil && database != nil {
			_ = updateUserPasskeyCredential(r.Context(), database, loggedInUser, credential)
		}
		_, _, _ = lim.recordFailure(waKey, now, loginMaxAttempts, loginWindow, loginWindow)
		uname := ""
		if loggedInUser != nil {
			uname = loggedInUser.Username
		}
		logger.Warn("Rejected cloned passkey authenticator for user '%s' from %s (SignCount=%d)", uname, clientIP, credential.Authenticator.SignCount)
		http.Error(w, "Invalid passkey authentication", http.StatusBadRequest)
		return
	}
	if loggedInUser != nil && credential != nil && database != nil {
		if err := updateUserPasskeyCredential(r.Context(), database, loggedInUser, credential); err != nil {
			s.internalError(w, r, "Failed to persist updated WebAuthn credential state", err)
			return
		}
	}
	lim.reset(waKey)
	loggedInUsername := ""
	if loggedInUser != nil {
		loggedInUsername = loggedInUser.Username
	}
	s.setJWTCookie(w, loggedInUsername)
	logger.Action("User '%s' logged in successfully via Passkey (WebAuthn) from %s", loggedInUsername, clientIP)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok", "redirect":"/"}`))
}
