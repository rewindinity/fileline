package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"fileline/internal/auth"
	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/storage"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

type ChunkUpload struct {
	ID           string
	OriginalName string
	CustomName   string
	URLPath      string
	TotalSize    int64
	TotalChunks  int
	IsPrivate    bool
	DriveID      string
	UserID       int
	Received     []bool
	TempDir      string
	CreatedAt    time.Time
}

// Server represents the HTTP server for the application.
type Server struct {
	httpServer *http.Server
	db         *sql.DB
	cfg        *config.Config
	// Storage
	storage       storage.Provider            // Default legacy provider
	storageDrives map[string]storage.Provider // Configured drives
	mu            sync.RWMutex
	tmpls         map[string]*template.Template
	webAuthn      *webauthn.WebAuthn
	// Temporary session stores
	totpTempStore     sync.Map // username -> string (secret)
	webAuthnTempStore sync.Map // sessionID -> webauthn.SessionData
	login2FAStore     sync.Map // sessionID -> username
	chunkMu           sync.RWMutex
	chunkUploads      map[string]*ChunkUpload
}

// New creates a new Server instance.
func New(cfg *config.Config, database *sql.DB) *Server {
	s := &Server{
		db:           database,
		cfg:          cfg,
		chunkUploads: make(map[string]*ChunkUpload),
	}
	// Parse templates safely for each page to avoid block overwriting
	s.tmpls = make(map[string]*template.Template)
	funcs := template.FuncMap{
		"FormatSize": func(b int64) string {
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			div, exp := int64(unit), 0
			for n := b / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
		},
	}
	pages := []string{"setup.html", "login.html", "dashboard.html", "404.html", "edit_file.html", "files.html", "settings.html", "settings_appearance.html", "settings_account.html", "settings_storage.html", "settings_subusers.html"}
	for _, page := range pages {
		t := template.New("base.html").Funcs(funcs)
		t, err := t.ParseFiles("web/templates/base.html", "web/templates/"+page)
		if err != nil {
			log.Printf("Warning: failed to parse template %s: %v", page, err)
		} else {
			s.tmpls[page] = t
		}
	}

	// Initialize storage if configured
	var st storage.Provider
	if cfg.StorageType != "" {
		st, _ = storage.NewProvider(context.Background(), cfg)
	}
	s.storage = st
	s.initDrives(context.Background())
	// Initialize WebAuthn
	schema := "http"
	if cfg.SSL || cfg.ReverseProxy {
		schema = "https"
	}
	domain := cfg.Domain
	// If domain does not contain a port and we are not behind a proxy with standard ports, append it
	if !strings.Contains(domain, ":") && !cfg.ReverseProxy {
		if (schema == "http" && cfg.Port != 80) || (schema == "https" && cfg.Port != 443) {
			domain = fmt.Sprintf("%s:%d", domain, cfg.Port)
		}
	}
	origin := fmt.Sprintf("%s://%s", schema, domain)
	wConfig := &webauthn.Config{
		RPDisplayName: "FileLine",
		RPID:          cfg.Domain, // RPID should not contain the port, just the domain
		RPOrigins:     []string{origin},
	}
	wa, err := webauthn.New(wConfig)
	if err != nil {
		log.Printf("Warning: failed to initialize WebAuthn: %v", err)
	}
	s.webAuthn = wa

	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("/health", s.healthHandler)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/logo", s.logoHandler)
	mux.HandleFunc("/favicon.ico", s.logoHandler)
	mux.HandleFunc("/setup", s.setupHandler)
	mux.HandleFunc("/login", s.loginHandler)
	mux.HandleFunc("/login/2fa", s.login2FAHandler)
	mux.HandleFunc("/logout", s.logoutHandler)
	mux.HandleFunc("/f/", s.serveFileHandler)
	mux.HandleFunc("/upload", s.requireAuth(s.uploadHandler))
	mux.HandleFunc("/api/upload/init", s.requireAuth(s.chunkUploadInitHandler))
	mux.HandleFunc("/api/upload/chunk", s.requireAuth(s.chunkUploadHandler))
	mux.HandleFunc("/api/upload/complete", s.requireAuth(s.chunkUploadCompleteHandler))
	mux.HandleFunc("/delete", s.requireAuth(s.deleteHandler))
	mux.HandleFunc("/files", s.requireAuth(s.filesHandler))
	mux.HandleFunc("/edit", s.requireAuth(s.editFileHandler))
	mux.HandleFunc("/settings", s.requireAuth(s.settingsHandler))
	mux.HandleFunc("/settings/action/", s.requireAuth(s.settingsActionHandler))
	mux.HandleFunc("/settings/appearance", s.requireAuth(s.settingsAppearanceHandler))
	mux.HandleFunc("/settings/account", s.requireAuth(s.settingsAccountHandler))
	mux.HandleFunc("/settings/storage", s.requireAuth(s.settingsStorageHandler))
	mux.HandleFunc("/settings/subusers", s.requireAuth(s.settingsSubusersHandler))
	mux.HandleFunc("/settings/users/add", s.requireAuth(s.addUserHandler))
	mux.HandleFunc("/settings/users/delete", s.requireAuth(s.deleteUserHandler))
	mux.HandleFunc("/settings/appearance/remove_logo", s.requireAuth(s.settingsRemoveLogoHandler))
	mux.HandleFunc("/settings/2fa/generate", s.requireAuth(s.totpGenerateHandler))
	mux.HandleFunc("/settings/2fa/verify", s.requireAuth(s.totpVerifyHandler))
	mux.HandleFunc("/settings/2fa/disable", s.requireAuth(s.totpDisableHandler))
	mux.HandleFunc("/webauthn/register/begin", s.requireAuth(s.webAuthnRegisterBegin))
	mux.HandleFunc("/webauthn/register/finish", s.requireAuth(s.webAuthnRegisterFinish))
	mux.HandleFunc("/settings/webauthn/delete", s.requireAuth(s.webAuthnDeleteHandler))
	mux.HandleFunc("/webauthn/login/begin", s.webAuthnLoginBegin)
	mux.HandleFunc("/webauthn/login/finish", s.webAuthnLoginFinish)
	mux.HandleFunc("/", s.requireAuth(s.dashboardHandler))

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

// Start begins listening for HTTP requests.
func (s *Server) Start() error {
	if s.cfg.SSL {
		if s.cfg.SSLCertPath == "" || s.cfg.SSLKeyPath == "" {
			return fmt.Errorf("SSL is enabled but cert or key path is missing")
		}
		s.httpServer.TLSConfig = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			PreferServerCipherSuites: true,
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		}
		fmt.Printf("Server listening on https://localhost:%d\n", s.cfg.Port)
		return s.httpServer.ListenAndServeTLS(s.cfg.SSLCertPath, s.cfg.SSLKeyPath)
	}
	fmt.Printf("Server listening on http://localhost:%d\n", s.cfg.Port)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) isConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return false
	}
	// Check if admin exists
	hasAdmin, err := db.HasAdmin(context.Background(), s.db)
	if err != nil || !hasAdmin {
		return false
	}
	return true
}

func (s *Server) renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	t, ok := s.tmpls[name]
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		log.Printf("Template not found: %s", name)
		return
	}
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("Error rendering template %s: %v", name, err)
	}
}

// Handlers
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	if database != nil {
		if err := database.PingContext(r.Context()); err != nil {
			http.Error(w, `{"status": "error", "message": "database unreachable"}`, http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "ok"}`))
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
		s.renderTemplate(w, "setup.html", map[string]interface{}{
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
			if dbType == "sqlite" {
				url := r.FormValue("sqlite_url")
				if url == "" {
					url = "data/database.sqlite"
				}
				importOS := true
				_ = importOS
				s.cfg.SQLiteURL = url
			} else if dbType == "postgres" {
				host := r.FormValue("pg_host")
				port := r.FormValue("pg_port")
				user := r.FormValue("pg_user")
				pass := r.FormValue("pg_password")
				dbname := r.FormValue("pg_db")
				s.cfg.PostgresURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, pass, host, port, dbname)
			} else {
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
		if storageType == "local" {
			localPath := r.FormValue("local_path")
			if localPath == "" {
				localPath = "./uploads"
			}
			s.cfg.LocalStoragePath = localPath
		} else if storageType == "s3" {
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
		// Login user automatically
		s.setJWTCookie(w, username)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) renderSetupError(w http.ResponseWriter, dbConfigured bool, errorMsg string) {
	s.renderTemplate(w, "setup.html", map[string]interface{}{
		"Title": "Setup", "Config": s.cfg,
		"DBConfigured": dbConfigured,
		"Error":        errorMsg,
	})
}

func (s *Server) loginHandler(w http.ResponseWriter, r *http.Request) {
	if !s.isConfigured() {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if r.Method == http.MethodGet {
		s.renderTemplate(w, "login.html", map[string]interface{}{
			"Title": "Setup", "Config": s.cfg,
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
			s.renderTemplate(w, "login.html", map[string]interface{}{
				"Title": "Login",
				"Error": "Invalid credentials",
			})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			s.renderTemplate(w, "login.html", map[string]interface{}{
				"Title": "Setup", "Config": s.cfg,
				"Error": "Invalid credentials",
			})
			return
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
			http.Redirect(w, r, "/login/2fa", http.StatusFound)
			return
		}
		s.setJWTCookie(w, username)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	filterID := user.ID
	if user.Role == "admin" {
		filterID = 0
	}

	files, err := db.GetRecentFiles(r.Context(), database, 10, filterID)
	if err != nil {
		http.Error(w, "Failed to load files", http.StatusInternalServerError)
		return
	}

	totalUsedBytes, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
	var enabledDrives []config.Drive
	for _, d := range s.cfg.Drives {
		if d.Enabled {
			enabledDrives = append(enabledDrives, d)
		}
	}

	s.renderTemplate(w, "dashboard.html", map[string]interface{}{
		"Title":          "Dashboard",
		"Username":       username,
		"User":           user,
		"Files":          files,
		"TotalUsedBytes": totalUsedBytes,
		"Config":         s.cfg,
		"EnabledDrives":  enabledDrives,
	})
}

// Middleware
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

func (s *Server) uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	r.ParseMultipartForm(10 << 20) // 10 MB limit
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	s.mu.RLock()
	maxSize := s.cfg.MaxUploadSizeMB * 1024 * 1024
	s.mu.RUnlock()
	if maxSize > 0 && header.Size > int64(maxSize) {
		http.Error(w, "File exceeds maximum allowed size", http.StatusBadRequest)
		return
	}

	originalName := header.Filename
	customName := r.FormValue("custom_name")
	urlPath := r.FormValue("url_path")
	if urlPath == "" {
		if customName != "" {
			urlPath = customName
		} else {
			urlPath = originalName
		}
	}

	isPrivate := r.FormValue("is_private") == "on"
	driveID := r.FormValue("drive_id")

	s.mu.RLock()
	st := s.getProvider(driveID)
	storageType := driveID
	if storageType == "" || storageType == "default" {
		storageType = s.cfg.StorageType
	}
	database := s.db
	s.mu.RUnlock()

	username := r.Context().Value("username").(string)
	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.StorageQuotaMB > 0 {
		total, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
		if total+header.Size > int64(user.StorageQuotaMB)*1024*1024 {
			http.Error(w, "Storage quota exceeded", http.StatusForbidden)
			return
		}
	}

	// Generate a unique storage key
	storageKey := fmt.Sprintf("%d-%s", time.Now().UnixNano(), originalName)

	if err := st.Save(r.Context(), storageKey, file); err != nil {
		http.Error(w, "Failed to save file to storage: "+err.Error(), http.StatusInternalServerError)
		return
	}

	f := &db.File{
		OriginalName: originalName,
		CustomName:   customName,
		URLPath:      urlPath,
		Size:         header.Size,
		IsPrivate:    isPrivate,
		StorageType:  storageType,
		StoragePath:  storageKey,
		UserID:       user.ID,
	}

	if err := db.InsertFile(r.Context(), database, f); err != nil {
		st.Delete(r.Context(), storageKey) // Rollback
		http.Error(w, "Failed to save file metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var id int
	fmt.Sscanf(r.FormValue("id"), "%d", &id)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	f, err := db.GetFileByID(r.Context(), database, id)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	username := r.Context().Value("username").(string)
	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.Role != "admin" && f.UserID != user.ID {
		s.renderTemplate(w, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
		return
	}
	s.mu.RLock()
	st := s.getProvider(f.StorageType)
	s.mu.RUnlock()
	if err := st.Delete(r.Context(), f.StoragePath); err != nil {
		log.Printf("Warning: failed to delete file from storage: %v", err)
	}

	db.DeleteFile(r.Context(), database, id)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) render404(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	s.renderTemplate(w, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg,})
}

func (s *Server) serveFileHandler(w http.ResponseWriter, r *http.Request) {
	urlPath := strings.TrimPrefix(r.URL.Path, "/f/")
	if urlPath == "" {
		s.render404(w)
		return
	}

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	f, err := db.GetFileByURL(r.Context(), database, urlPath)
	if err != nil {
		s.render404(w)
		return
	}

	if f.IsPrivate {
		// Check auth manually
		cookie, err := r.Cookie("session")
		if err != nil {
			s.render404(w)
			return
		}
		token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
			s.mu.RLock()
			key := []byte(s.cfg.JWTKey)
			s.mu.RUnlock()
			return key, nil
		})
		if err != nil || !token.Valid {
			s.render404(w)
			return
		}
	}
	s.mu.RLock()
	st := s.getProvider(f.StorageType)
	s.mu.RUnlock()
	reader, err := st.Get(r.Context(), f.StoragePath)
	if err != nil {
		s.render404(w)
		return
	}
	defer reader.Close()

	// Provide original filename for download if custom_name is used, otherwise original
	downloadName := f.OriginalName
	if f.CustomName != "" {
		downloadName = f.CustomName
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, downloadName))
	io.Copy(w, reader)
}

func (s *Server) filesHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	filterID := user.ID
	if user.Role == "admin" {
		filterID = 0
	}
	files, err := db.GetAllFiles(r.Context(), database, filterID)
	if err != nil {
		http.Error(w, "Failed to load files", http.StatusInternalServerError)
		return
	}
	s.renderTemplate(w, "files.html", map[string]interface{}{
		"Title":    "All Files",
		"Username": username,
		"User":     user,
		"Files":    files,
	})
}

func (s *Server) editFileHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	if r.Method == http.MethodGet {
		var id int
		fmt.Sscanf(r.URL.Query().Get("id"), "%d", &id)
		f, err := db.GetFileByID(r.Context(), database, id)
		if err != nil {
			s.render404(w)
			return
		}
		user, _ := db.GetUserByUsername(r.Context(), database, username)
		if user.Role != "admin" && f.UserID != user.ID {
			s.renderTemplate(w, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
			return
		}
		s.renderTemplate(w, "edit_file.html", map[string]interface{}{
			"Title":    "Edit File",
			"Username": username,
			"User":     user,
			"File":     f,
		})
		return
	}

	if r.Method == http.MethodPost {
		var id int
		fmt.Sscanf(r.FormValue("id"), "%d", &id)
		f, err := db.GetFileByID(r.Context(), database, id)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		user, _ := db.GetUserByUsername(r.Context(), database, username)
		if user.Role != "admin" && f.UserID != user.ID {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		customName := r.FormValue("custom_name")
		urlPath := r.FormValue("url_path")
		isPrivate := r.FormValue("is_private") == "on"
		if err := db.UpdateFile(r.Context(), database, id, customName, urlPath, isPrivate); err != nil {
			http.Error(w, "Failed to update file", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, "/files", http.StatusFound)
	}
}

func (s *Server) settingsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()

	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	user, _ := db.GetUserByUsername(r.Context(), database, username)

	var passkeys []auth.Passkey
	if user.WebAuthnData != "" {
		json.Unmarshal([]byte(user.WebAuthnData), &passkeys)
	}
	var passkeysDisplay []map[string]interface{}
	for i, pk := range passkeys {
		name := pk.Name
		if name == "" {
			name = fmt.Sprintf("Passkey %d", i+1)
		}
		passkeysDisplay = append(passkeysDisplay, map[string]interface{}{
			"Index": i + 1,
			"Name":  name,
			"ID":    base64.URLEncoding.EncodeToString(pk.Credential.ID),
		})
	}
	var allUsers []*db.User
	if user.Role == "admin" {
		allUsers, _ = db.GetAllUsers(r.Context(), database)
	}
	drivesJSONBytes, _ := json.MarshalIndent(cfg.Drives, "", "  ")
	if string(drivesJSONBytes) == "null" {
		drivesJSONBytes = []byte("[]")
	}
	s.renderTemplate(w, "settings.html", map[string]interface{}{
		"Title":          "Settings",
		"Username":       username,
		"User":           user,
		"AllUsers":       allUsers,
		"Passkeys":       passkeysDisplay,
		"Config":         cfg,
		"DrivesJSON":     string(drivesJSONBytes),
		"EnvOnly":        cfg.EnvOnly,
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
	})
}

func (s *Server) addUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.Role != "admin" {
		s.renderTemplate(w, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
		return
	}
	newUsername := r.FormValue("new_username")
	newPassword := r.FormValue("new_password")
	var quotaMB int
	fmt.Sscanf(r.FormValue("new_quota"), "%d", &quotaMB)
	if newUsername == "" || newPassword == "" {
		http.Redirect(w, r, "/settings/subusers?error=Invalid+user+data", http.StatusFound)
		return
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err := db.CreateSubuser(r.Context(), database, newUsername, string(hash), quotaMB); err != nil {
		http.Redirect(w, r, "/settings/subusers?error=Failed+to+create+user", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/settings/subusers?success=User+created+successfully", http.StatusFound)
}

func (s *Server) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.Role != "admin" {
		s.renderTemplate(w, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
		return
	}
	targetUser := r.FormValue("username")
	if targetUser == username {
		http.Redirect(w, r, "/settings/subusers?error=Cannot+delete+yourself", http.StatusFound)
		return
	}
	if err := db.DeleteUser(r.Context(), database, targetUser); err != nil {
		http.Redirect(w, r, "/settings/subusers?error=Failed+to+delete+user", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/settings/subusers?success=User+deleted+successfully", http.StatusFound)
}

func (s *Server) settingsActionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	username := r.Context().Value("username").(string)
	action := strings.TrimPrefix(r.URL.Path, "/settings/action/")

	if action == "storage" {
		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()
		user, _ := db.GetUserByUsername(r.Context(), database, username)
		if user.Role != "admin" {
			s.renderTemplate(w, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
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
		if storageType == "local" {
			localPath := r.FormValue("local_path")
			if localPath == "" {
				localPath = "./uploads"
			}
			s.cfg.LocalStoragePath = localPath
		} else if storageType == "s3" {
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
				s.cfg.Drives = newDrives
			} else {
				log.Printf("Warning: failed to parse drives_json: %v", err)
			}
		}
		s.cfg.Save("config.json")
		// Reinit storage
		st, err := storage.NewProvider(r.Context(), s.cfg)
		if err == nil {
			s.storage = st
		} else {
			log.Printf("Failed to reinitialize storage: %v", err)
		}
		s.initDrives(r.Context())
		s.mu.Unlock()
		http.Redirect(w, r, "/settings/storage?success=Storage+settings+saved", http.StatusFound)
		return
	}

	if action == "appearance" {
		theme := r.FormValue("theme")
		var accent string
		if r.FormValue("use_global_accent") == "on" {
			accent = "global"
		} else {
			accent = r.FormValue("accent")
		}
		if theme == "" {
			theme = "global"
		}
		if accent == "" {
			accent = "global"
		}

		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()

		user, err := db.GetUserByUsername(r.Context(), database, username)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		err = db.UpdateUserTheme(r.Context(), database, username, theme, accent)
		if err != nil {
			http.Redirect(w, r, "/settings/appearance?error=Failed+to+update+theme", http.StatusFound)
			return
		}

		if user.Role == "admin" {
			globalTheme := r.FormValue("global_theme")
			customAccentHex := r.FormValue("custom_accent_hex")
			s.mu.Lock()
			if globalTheme != "" {
				s.cfg.Theme = globalTheme
			}
			if customAccentHex != "" {
				s.cfg.CustomAccentHex = customAccentHex
			}
			s.cfg.Save("config.json")
			s.mu.Unlock()
			err = r.ParseMultipartForm(32 << 20)
			if err != nil {
				fmt.Println("ParseMultipartForm error:", err)
			} else {
				fmt.Printf("MultipartForm files: %v\n", r.MultipartForm.File)
			}

			// Handle custom logo upload
			file, header, err := r.FormFile("custom_logo_file")
			if err == nil {
				defer file.Close()
				ext := strings.ToLower(filepath.Ext(header.Filename))
				if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".svg" {
					blob, ioErr := io.ReadAll(file)
					if ioErr == nil && len(blob) > 0 {
						filename := "custom-logo" + ext
						writeErr := os.WriteFile(filepath.Join("data", filename), blob, 0644)
						if writeErr == nil {
							s.mu.Lock()
							s.cfg.CustomLogo = filename
							s.cfg.Save("config.json")
							s.mu.Unlock()
						} else {
							fmt.Println("WriteFile error:", writeErr)
							http.Redirect(w, r, "/settings/appearance?error=Failed+to+write+logo", http.StatusFound)
							return
						}
					} else {
						fmt.Println("ReadAll error:", ioErr)
						http.Redirect(w, r, "/settings/appearance?error=Failed+to+read+logo+file", http.StatusFound)
						return
					}
				} else {
					fmt.Println("Invalid extension:", ext)
					http.Redirect(w, r, "/settings/appearance?error=Invalid+logo+extension.+Only+PNG,+JPG,+SVG+allowed.", http.StatusFound)
					return
				}
			} else if err != http.ErrMissingFile {
				fmt.Println("FormFile error:", err)
				http.Redirect(w, r, "/settings/appearance?error=Failed+to+process+logo+upload", http.StatusFound)
				return
			}
		}

		http.Redirect(w, r, "/settings/appearance?success=Appearance+updated", http.StatusFound)
		return
	}

	if action == "password" {
		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()
		user, err := db.GetUserByUsername(r.Context(), database, username)
		if err != nil {
			http.Redirect(w, r, "/settings/account?error=User+not+found", http.StatusFound)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword)); err != nil {
			http.Redirect(w, r, "/settings/account?error=Incorrect+current+password", http.StatusFound)
			return
		}
		newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Redirect(w, r, "/settings/account?error=Failed+to+secure+password", http.StatusFound)
			return
		}
		if err := db.UpdatePassword(r.Context(), database, username, string(newHash)); err != nil {
			http.Redirect(w, r, "/settings/account?error=Failed+to+update+password", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/settings/account?success=Password+updated+successfully", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// Helpers for random strings
func generateRandomSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) totpGenerateHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "FileLine",
		AccountName: username,
	})
	if err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+generate+2FA", http.StatusFound)
		return
	}
	// Save temporary
	s.totpTempStore.Store(username, key.Secret())
	// Generate QR Code
	var png []byte
	png, err = qrcode.Encode(key.String(), qrcode.Medium, 256)
	if err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+generate+QR", http.StatusFound)
		return
	}
	qrBase64 := base64.StdEncoding.EncodeToString(png)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf(`
		<h2>Scan this QR Code</h2>
		<img src="data:image/png;base64,%s" />
		<p>Secret: %s</p>
		<form method="POST" action="/settings/2fa/verify">
			<input type="text" name="code" placeholder="6-digit code" required />
			<button type="submit">Verify & Enable</button>
		</form>
		<a href="/settings">Cancel</a>
	`, qrBase64, key.Secret())))
}

func (s *Server) totpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)
	code := r.FormValue("code")

	secretAny, ok := s.totpTempStore.Load(username)
	if !ok {
		http.Redirect(w, r, "/settings/account?error=2FA+session+expired", http.StatusFound)
		return
	}
	secret := secretAny.(string)

	if !totp.Validate(code, secret) {
		http.Redirect(w, r, "/setting/accounts?error=Invalid+code", http.StatusFound)
		return
	}

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err == nil {
		db.UpdateUserAuthData(r.Context(), database, username, secret, user.WebAuthnData)
	}

	s.totpTempStore.Delete(username)
	http.Redirect(w, r, "/settings/account?success=2FA+Enabled+Successfully", http.StatusFound)
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

	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`
			<h2>Enter 2FA Code</h2>
			<form method="POST" action="/login/2fa">
				<input type="text" name="code" required autofocus />
				<button type="submit">Verify</button>
			</form>
		`))
		return
	}

	if r.Method == http.MethodPost {
		code := r.FormValue("code")
		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()
		user, err := db.GetUserByUsername(r.Context(), database, username)
		if err != nil || user.TOTPSecret == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if !totp.Validate(code, user.TOTPSecret) {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<h2>Invalid Code</h2><a href="/login/2fa">Try again</a>`))
			return
		}
		// Success
		s.login2FAStore.Delete(sessionID)
		s.setJWTCookie(w, username)
		http.Redirect(w, r, "/", http.StatusFound)
	}
}

func (s *Server) webAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	dbUser, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	user := auth.NewWebAuthnUser(dbUser)
	options, sessionData, err := s.webAuthn.BeginRegistration(
		user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	sessionID := generateRandomSessionID()
	s.webAuthnTempStore.Store(sessionID, *sessionData)
	http.SetCookie(w, &http.Cookie{
		Name:     "wa_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func (s *Server) webAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	cookie, err := r.Cookie("wa_session")
	if err != nil {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}

	sessionDataAny, ok := s.webAuthnTempStore.Load(cookie.Value)
	if !ok {
		http.Error(w, "Session expired", http.StatusBadRequest)
		return
	}
	sessionData := sessionDataAny.(webauthn.SessionData)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	dbUser, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}
	user := auth.NewWebAuthnUser(dbUser)
	credential, err := s.webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	passkeyName := r.URL.Query().Get("name")
	if passkeyName == "" {
		passkeyName = "Passkey " + time.Now().Format("2006-01-02 15:04")
	}
	var passkeys []auth.Passkey
	if dbUser.WebAuthnData != "" {
		_ = json.Unmarshal([]byte(dbUser.WebAuthnData), &passkeys)
	}
	newPasskey := auth.Passkey{
		Credential: *credential,
		Name:       passkeyName,
	}
	passkeys = append(passkeys, newPasskey)
	credsJSON, _ := json.Marshal(passkeys)
	if err := db.UpdateUserAuthData(r.Context(), database, username, dbUser.TOTPSecret, string(credsJSON)); err != nil {
		http.Error(w, "Failed to save credential", http.StatusInternalServerError)
		return
	}
	s.webAuthnTempStore.Delete(cookie.Value)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) webAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, sessionData, err := s.webAuthn.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.webAuthnTempStore.Delete(sessionID)
	s.setJWTCookie(w, loggedInUsername)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok", "redirect":"/"}`))
}
func (s *Server) totpDisableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)
	code := r.FormValue("code")

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.TOTPSecret == "" {
		http.Redirect(w, r, "/settings/account?error=2FA+is+not+enabled", http.StatusFound)
		return
	}
	if !totp.Validate(code, user.TOTPSecret) {
		http.Redirect(w, r, "/settings/account?error=Invalid+2FA+code", http.StatusFound)
		return
	}
	if err := db.UpdateUserAuthData(r.Context(), database, username, "", user.WebAuthnData); err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+disable+2FA", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/settings/account?success=2FA+Disabled+Successfully", http.StatusFound)
}

func (s *Server) webAuthnDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	username := r.Context().Value("username").(string)
	idToDelete := r.FormValue("id")

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.WebAuthnData == "" {
		http.Redirect(w, r, "/settings/account?error=User+or+passkeys+not+found", http.StatusFound)
		return
	}

	var passkeys []auth.Passkey
	if err := json.Unmarshal([]byte(user.WebAuthnData), &passkeys); err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+parse+passkeys", http.StatusFound)
		return
	}

	var updatedPasskeys []auth.Passkey
	deleted := false
	for _, pk := range passkeys {
		encodedID := base64.URLEncoding.EncodeToString(pk.Credential.ID)
		if encodedID == idToDelete {
			deleted = true
			continue
		}
		updatedPasskeys = append(updatedPasskeys, pk)
	}

	if !deleted {
		http.Redirect(w, r, "/settings/account?error=Passkey+not+found", http.StatusFound)
		return
	}
	var updatedJSON []byte
	if len(updatedPasskeys) > 0 {
		updatedJSON, _ = json.Marshal(updatedPasskeys)
	} else {
		updatedJSON = []byte("[]")
	}
	if err := db.UpdateUserAuthData(r.Context(), database, username, user.TOTPSecret, string(updatedJSON)); err != nil {
		http.Redirect(w, r, "/settings/account?error=Failed+to+delete+passkey", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/settings/account?success=Passkey+deleted+successfully", http.StatusFound)
}

func (s *Server) chunkUploadInitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		FileName    string `json:"file_name"`
		TotalSize   int64  `json:"total_size"`
		TotalChunks int    `json:"total_chunks"`
		IsPrivate   bool   `json:"is_private"`
		CustomName  string `json:"custom_name"`
		URLPath     string `json:"url_path"`
		DriveID     string `json:"drive_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	maxSize := s.cfg.MaxUploadSizeMB * 1024 * 1024
	s.mu.RUnlock()
	if maxSize > 0 && req.TotalSize > int64(maxSize) {
		http.Error(w, "File exceeds maximum allowed size", http.StatusBadRequest)
		return
	}
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if user.StorageQuotaMB > 0 {
		total, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
		if total+req.TotalSize > int64(user.StorageQuotaMB)*1024*1024 {
			http.Error(w, "Storage quota exceeded", http.StatusForbidden)
			return
		}
	}
	uploadID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), req.FileName)
	tempDir := filepath.Join(os.TempDir(), "fileline_chunks", uploadID)
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		http.Error(w, "Failed to create temp directory", http.StatusInternalServerError)
		return
	}

	upload := &ChunkUpload{
		ID:           uploadID,
		OriginalName: req.FileName,
		CustomName:   req.CustomName,
		URLPath:      req.URLPath,
		TotalSize:    req.TotalSize,
		TotalChunks:  req.TotalChunks,
		IsPrivate:    req.IsPrivate,
		DriveID:      req.DriveID,
		UserID:       user.ID,
		Received:     make([]bool, req.TotalChunks),
		TempDir:      tempDir,
		CreatedAt:    time.Now(),
	}
	s.chunkMu.Lock()
	s.chunkUploads[uploadID] = upload
	s.chunkMu.Unlock()

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
	r.ParseMultipartForm(32 << 20) // 32MB max memory for parsing
	uploadID := r.FormValue("upload_id")
	chunkIndex, err := strconv.Atoi(r.FormValue("chunk_index"))
	if err != nil {
		http.Error(w, "Invalid chunk index", http.StatusBadRequest)
		return
	}
	file, _, err := r.FormFile("chunk")
	if err != nil {
		http.Error(w, "Failed to read chunk", http.StatusBadRequest)
		return
	}
	defer file.Close()
	s.chunkMu.RLock()
	upload, ok := s.chunkUploads[uploadID]
	s.chunkMu.RUnlock()
	if !ok {
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}
	if chunkIndex < 0 || chunkIndex >= upload.TotalChunks {
		http.Error(w, "Chunk index out of bounds", http.StatusBadRequest)
		return
	}
	chunkPath := filepath.Join(upload.TempDir, fmt.Sprintf("%d", chunkIndex))
	dst, err := os.Create(chunkPath)
	if err != nil {
		http.Error(w, "Failed to save chunk to disk", http.StatusInternalServerError)
		return
	}
	io.Copy(dst, file)
	dst.Close()
	s.chunkMu.Lock()
	upload.Received[chunkIndex] = true
	s.chunkMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) chunkUploadCompleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		UploadID string `json:"upload_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	s.chunkMu.RLock()
	upload, ok := s.chunkUploads[req.UploadID]
	s.chunkMu.RUnlock()
	if !ok {
		http.Error(w, "Upload session not found", http.StatusNotFound)
		return
	}
	for i, received := range upload.Received {
		if !received {
			http.Error(w, fmt.Sprintf("Missing chunk %d", i), http.StatusBadRequest)
			return
		}
	}

	// Assemble file
	assembledPath := filepath.Join(upload.TempDir, "assembled")
	finalFile, err := os.Create(assembledPath)
	if err != nil {
		http.Error(w, "Failed to create assembled file", http.StatusInternalServerError)
		return
	}

	var actualSize int64
	for i := 0; i < upload.TotalChunks; i++ {
		chunkPath := filepath.Join(upload.TempDir, fmt.Sprintf("%d", i))
		chunkData, err := os.ReadFile(chunkPath)
		if err != nil {
			finalFile.Close()
			http.Error(w, "Failed to read chunk from disk", http.StatusInternalServerError)
			return
		}
		n, err := finalFile.Write(chunkData)
		if err != nil {
			finalFile.Close()
			http.Error(w, "Failed to write assembled file", http.StatusInternalServerError)
			return
		}
		actualSize += int64(n)
	}
	finalFile.Close()

	// Clean up temp dir and session after we are done storing
	defer func() {
		os.RemoveAll(upload.TempDir)
		s.chunkMu.Lock()
		delete(s.chunkUploads, upload.ID)
		s.chunkMu.Unlock()
	}()

	// Re-open for storage provider
	assembledFile, err := os.Open(assembledPath)
	if err != nil {
		http.Error(w, "Failed to open assembled file", http.StatusInternalServerError)
		return
	}
	defer assembledFile.Close()

	urlPath := upload.URLPath
	if urlPath == "" {
		if upload.CustomName != "" {
			urlPath = upload.CustomName
		} else {
			urlPath = upload.OriginalName
		}
	}

	s.mu.RLock()
	st := s.getProvider(upload.DriveID)
	storageType := upload.DriveID
	if storageType == "" || storageType == "default" {
		storageType = s.cfg.StorageType
	}
	database := s.db
	s.mu.RUnlock()
	storageKey := fmt.Sprintf("%d-%s", time.Now().UnixNano(), upload.OriginalName)
	if err := st.Save(r.Context(), storageKey, assembledFile); err != nil {
		http.Error(w, "Failed to save file to storage: "+err.Error(), http.StatusInternalServerError)
		return
	}

	f := &db.File{
		OriginalName: upload.OriginalName,
		CustomName:   upload.CustomName,
		URLPath:      urlPath,
		Size:         actualSize,
		IsPrivate:    upload.IsPrivate,
		StorageType:  storageType,
		StoragePath:  storageKey,
		UserID:       upload.UserID,
	}

	if err := db.InsertFile(r.Context(), database, f); err != nil {
		st.Delete(r.Context(), storageKey) // Rollback
		http.Error(w, "Failed to save file metadata: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func (s *Server) initDrives(ctx context.Context) {
	s.storageDrives = make(map[string]storage.Provider)
	for _, drive := range s.cfg.Drives {
		p, err := storage.NewProviderFromDrive(ctx, drive)
		if err == nil {
			s.storageDrives[drive.ID] = p
		} else {
			log.Printf("Warning: failed to initialize drive %s: %v", drive.Name, err)
		}
	}
}

func (s *Server) getProvider(driveID string) storage.Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.storageDrives[driveID]; ok {
		return p
	}
	// Fallback to default
	return s.storage
}

func (s *Server) logoHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	customLogo := s.cfg.CustomLogo
	s.mu.RUnlock()
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if customLogo == "" || customLogo == "/static/logo.svg" {
		http.ServeFile(w, r, "web/static/logo.svg")
		return
	}
	logoPath := filepath.Join("data", customLogo)
	if _, err := os.Stat(logoPath); err == nil {
		http.ServeFile(w, r, logoPath)
	} else {
		http.ServeFile(w, r, "web/static/logo.svg")
	}
}

func (s *Server) settingsRemoveLogoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusFound)
		return
	}
	username, ok := r.Context().Value("username").(string)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	user, err := db.GetUserByUsername(r.Context(), database, username)
	if err != nil || user.Role != "admin" {
		http.Redirect(w, r, "/settings/appearance?error=Unauthorized", http.StatusFound)
		return
	}
	s.mu.Lock()
	oldLogo := s.cfg.CustomLogo
	s.cfg.CustomLogo = "/static/logo.svg"
	s.cfg.Save("config.json")
	s.mu.Unlock()
	// Optionally delete the file
	if oldLogo != "" && oldLogo != "/static/logo.svg" {
		os.Remove(filepath.Join("data", oldLogo))
	}
	http.Redirect(w, r, "/settings/appearance?success=Custom+logo+removed", http.StatusFound)
}

func (s *Server) settingsAppearanceHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()
	user, _ := db.GetUserByUsername(r.Context(), database, username)
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, "settings_appearance.html", map[string]interface{}{
		"Title": "Appearance Settings",
		"Username": username,
		"User": user,
		"Config": cfg,
		"SuccessMessage": successMsg,
		"ErrorMessage": errorMsg,
	})
}

func (s *Server) settingsAccountHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()
	user, _ := db.GetUserByUsername(r.Context(), database, username)
	var passkeys []auth.Passkey
	if user.WebAuthnData != "" {
		json.Unmarshal([]byte(user.WebAuthnData), &passkeys)
	}
	var passkeysDisplay []map[string]interface{}
	for i, pk := range passkeys {
		name := pk.Name
		if name == "" {
			name = fmt.Sprintf("Passkey %d", i+1)
		}
		passkeysDisplay = append(passkeysDisplay, map[string]interface{}{
			"Index":  i + 1,
			"Name":   name,
			"ID":     base64.URLEncoding.EncodeToString(pk.Credential.ID),
		})
	}
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, "settings_account.html", map[string]interface{}{
		"Title": "Account Settings",
		"Username": username,
		"User": user,
		"Config": cfg,
		"Passkeys": passkeysDisplay,
		"SuccessMessage": successMsg,
		"ErrorMessage": errorMsg,
	})
}

func (s *Server) settingsStorageHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()
	user, _ := db.GetUserByUsername(r.Context(), database, username)
	if user.Role != "admin" {
		s.renderTemplate(w, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
		return
	}
	drivesJSONBytes, _ := json.MarshalIndent(cfg.Drives, "", "  ")
	if string(drivesJSONBytes) == "null" {
		drivesJSONBytes = []byte("[]")
	}
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, "settings_storage.html", map[string]interface{}{
		"Title": "Storage Settings",
		"Username": username,
		"User": user,
		"Config": cfg,
		"DrivesJSON": string(drivesJSONBytes),
		"EnvOnly": cfg.EnvOnly,
		"SuccessMessage": successMsg,
		"ErrorMessage": errorMsg,
	})
}

func (s *Server) settingsSubusersHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()
	user, _ := db.GetUserByUsername(r.Context(), database, username)
	if user.Role != "admin" {
		s.renderTemplate(w, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
		return
	}
	allUsers, _ := db.GetAllUsers(r.Context(), database)
	type userDisplay struct {
		User               *db.User
		FormattedTotalUsed string
	}
	var displayUsers []userDisplay
	for _, u := range allUsers {
		total, _ := db.GetUserTotalStorage(r.Context(), database, u.ID)
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
	s.renderTemplate(w, "settings_subusers.html", map[string]interface{}{
		"Title": "Subusers Settings",
		"Username": username,
		"User": user,
		"Config": cfg,
		"AllUsers": displayUsers,
		"SuccessMessage": successMsg,
		"ErrorMessage": errorMsg,
	})
}