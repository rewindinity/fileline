package server

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/storage"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Server represents the HTTP server for the application.
type Server struct {
	httpServer *http.Server
	db         *sql.DB
	cfg        *config.Config
	mu         sync.RWMutex
	tmpls      map[string]*template.Template
	storage    storage.Provider
}

// New creates a new Server instance.
func New(cfg *config.Config, database *sql.DB) *Server {
	s := &Server{
		db:  database,
		cfg: cfg,
	}
	// Parse templates safely for each page to avoid block overwriting
	s.tmpls = make(map[string]*template.Template)
	pages := []string{"setup.html", "login.html", "dashboard.html", "404.html", "edit_file.html", "files.html", "settings.html"}
	for _, page := range pages {
		t, err := template.ParseFiles("web/templates/base.html", "web/templates/"+page)
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

	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/setup", s.setupHandler)
	mux.HandleFunc("/login", s.loginHandler)
	mux.HandleFunc("/logout", s.logoutHandler)
	mux.HandleFunc("/f/", s.serveFileHandler)
	mux.HandleFunc("/upload", s.requireAuth(s.uploadHandler))
	mux.HandleFunc("/delete", s.requireAuth(s.deleteHandler))
	mux.HandleFunc("/files", s.requireAuth(s.filesHandler))
	mux.HandleFunc("/edit", s.requireAuth(s.editFileHandler))
	mux.HandleFunc("/settings", s.requireAuth(s.settingsHandler))
	mux.HandleFunc("/settings/", s.requireAuth(s.settingsActionHandler))
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
		// Configure modern TLS settings
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
			"Title":        "Setup",
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
		"Title":        "Setup",
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
			"Title": "Login",
		})
		return
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()
		_, hash, _, err := db.GetUserByUsername(r.Context(), database, username)
		if err != nil {
			s.renderTemplate(w, "login.html", map[string]interface{}{
				"Title": "Login",
				"Error": "Invalid credentials",
			})
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
			s.renderTemplate(w, "login.html", map[string]interface{}{
				"Title": "Login",
				"Error": "Invalid credentials",
			})
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

	files, err := db.GetRecentFiles(r.Context(), database, 10)
	if err != nil {
		http.Error(w, "Failed to load files", http.StatusInternalServerError)
		return
	}
	s.renderTemplate(w, "dashboard.html", map[string]interface{}{
		"Title":    "Dashboard",
		"Username": username,
		"Files":    files,
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

	s.mu.RLock()
	storageType := s.cfg.StorageType
	st := s.storage
	database := s.db
	s.mu.RUnlock()

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
	st := s.storage
	s.mu.RUnlock()

	f, err := db.GetFileByID(r.Context(), database, id)
	if err != nil {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	if err := st.Delete(r.Context(), f.StoragePath); err != nil {
		log.Printf("Warning: failed to delete file from storage: %v", err)
	}

	db.DeleteFile(r.Context(), database, id)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) render404(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	s.renderTemplate(w, "404.html", map[string]interface{}{"Title": "Not Found"})
}

func (s *Server) serveFileHandler(w http.ResponseWriter, r *http.Request) {
	urlPath := strings.TrimPrefix(r.URL.Path, "/f/")
	if urlPath == "" {
		s.render404(w)
		return
	}

	s.mu.RLock()
	database := s.db
	st := s.storage
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
			return []byte(s.cfg.JWTKey), nil
		})
		if err != nil || !token.Valid {
			s.render404(w)
			return
		}
	}

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

	files, err := db.GetAllFiles(r.Context(), database)
	if err != nil {
		http.Error(w, "Failed to load files", http.StatusInternalServerError)
		return
	}
	s.renderTemplate(w, "files.html", map[string]interface{}{
		"Title":    "All Files",
		"Username": username,
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
		s.renderTemplate(w, "edit_file.html", map[string]interface{}{
			"Title":    "Edit File",
			"Username": username,
			"File":     f,
		})
		return
	}

	if r.Method == http.MethodPost {
		var id int
		fmt.Sscanf(r.FormValue("id"), "%d", &id)
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
	s.mu.RUnlock()

	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")

	s.renderTemplate(w, "settings.html", map[string]interface{}{
		"Title":          "Settings",
		"Username":       username,
		"Config":         cfg,
		"EnvOnly":        cfg.EnvOnly,
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
	})
}

func (s *Server) settingsActionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	username := r.Context().Value("username").(string)
	action := strings.TrimPrefix(r.URL.Path, "/settings/")

	if action == "storage" {
		s.mu.Lock()
		if s.cfg.EnvOnly {
			s.mu.Unlock()
			http.Redirect(w, r, "/settings?error=Cannot+modify+storage+in+ENV-only+mode", http.StatusFound)
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
		s.cfg.Save("config.json")
		// Reinit storage
		st, err := storage.NewProvider(r.Context(), s.cfg)
		if err == nil {
			s.storage = st
		} else {
			log.Printf("Failed to reinitialize storage: %v", err)
		}
		s.mu.Unlock()
		http.Redirect(w, r, "/settings?success=Storage+settings+saved", http.StatusFound)
		return
	}

	if action == "password" {
		currentPassword := r.FormValue("current_password")
		newPassword := r.FormValue("new_password")
		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()
		_, hash, _, err := db.GetUserByUsername(r.Context(), database, username)
		if err != nil {
			http.Redirect(w, r, "/settings?error=User+not+found", http.StatusFound)
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(currentPassword)); err != nil {
			http.Redirect(w, r, "/settings?error=Incorrect+current+password", http.StatusFound)
			return
		}
		newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Redirect(w, r, "/settings?error=Failed+to+secure+password", http.StatusFound)
			return
		}
		if err := db.UpdatePassword(r.Context(), database, username, string(newHash)); err != nil {
			http.Redirect(w, r, "/settings?error=Failed+to+update+password", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/settings?success=Password+updated+successfully", http.StatusFound)
		return
	}

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
