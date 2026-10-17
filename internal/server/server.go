package server

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/storage"
	"fileline/internal/translations"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Server represents the HTTP server for the application.
type Server struct {
	httpServer *http.Server
	db         *sql.DB
	cfg        *config.Config
	// Storage
	storage       storage.Provider            // Default legacy provider
	storageDrives map[string]storage.Provider // Configured drives
	mu            sync.RWMutex
	setupMu       sync.Mutex
	configured    atomic.Bool
	setupToken    string
	tmpls         map[string]*template.Template
	webAuthn      *webauthn.WebAuthn
	// Temporary session stores
	totpTempStore     sync.Map // username -> string (secret)
	webAuthnTempStore sync.Map // sessionID -> webauthn.SessionData
	login2FAStore     sync.Map // sessionID -> *twoFASession
	login2FAMu        sync.Mutex
	recoveryCodeStore sync.Map // username -> string (newly generated recovery code to display)
	authLimiter       *authRateLimiter
	chunkMu           sync.RWMutex
	chunkUploads      map[string]*ChunkUpload
	stopOnce          sync.Once
	stopCh            chan struct{}
}

// New creates a new Server instance and configures its dependencies and routes.
func New(cfg *config.Config, database *sql.DB) *Server {
	if cfg != nil {
		logger.SetDebug(cfg.Debug)
		if !config.IsValidJWTKey(cfg.JWTKey) {
			if key, err := config.GenerateJWTKey(); err == nil {
				cfg.JWTKey = key
			}
		}
	}
	s := &Server{
		db:           database,
		cfg:          cfg,
		authLimiter:  newAuthRateLimiter(),
		chunkUploads: make(map[string]*ChunkUpload),
		stopCh:       make(chan struct{}),
	}
	go s.runBackgroundJanitor()
	if database != nil {
		if hasAdmin, err := db.HasAdmin(context.Background(), database); err == nil && hasAdmin {
			s.configured.Store(true)
		}
	}
	// Parse templates safely for each page to avoid block overwriting
	s.tmpls = make(map[string]*template.Template)
	funcs := template.FuncMap{
		"FormatSize": func(b int64) string {
			return logger.FormatBytes(b)
		},
		"FormatPercent": func(p float64) string {
			return fmt.Sprintf("%.1f%%", p)
		},
		"FormatPercentRaw": func(p float64) string {
			return fmt.Sprintf("%.1f", p)
		},
		"FormatTime": func(t *time.Time) string {
			if t == nil {
				return ""
			}
			return t.Format("Jan 02, 2006 15:04")
		},
		"T": func(lang, key string) string {
			return translations.GetString(lang, key)
		},
	}
	pages := []string{
		"setup.html", "login.html", "login_2fa.html", "reset_password.html", "dashboard.html", "404.html", "edit_file.html", "files.html", "settings.html",
		"settings_appearance.html", "settings_embed.html", "settings_account.html", "settings_storage.html", "settings_subusers.html",
	}
	templateDir := "web/templates"
	if _, err := os.Stat(filepath.Join(templateDir, "base.html")); err != nil {
		if _, err2 := os.Stat(filepath.Join("../../web/templates", "base.html")); err2 == nil {
			templateDir = "../../web/templates"
		}
	}
	for _, page := range pages {
		basePath := filepath.Join(templateDir, "base.html")
		pagePath := filepath.Join(templateDir, page)
		t := template.New("base.html").Funcs(funcs)
		t, err := t.ParseFiles(basePath, pagePath)
		if err != nil {
			logger.Error("Failed to parse template %s: %v", page, err)
		} else {
			s.tmpls[page] = t
		}
	}
	embedPagePath := filepath.Join(templateDir, "embed_file.html")
	if tEmbed, err := template.New("embed_file.html").Funcs(funcs).ParseFiles(embedPagePath); err != nil {
		logger.Error("Failed to parse template embed_file.html: %v", err)
	} else {
		s.tmpls["embed_file.html"] = tEmbed
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
		logger.Error("Failed to initialize WebAuthn: %v", err)
	}
	s.webAuthn = wa

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      s.routes(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s
}

// routes registers all HTTP handlers and returns the configured ServeMux.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	// Base & System routes
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/robots.txt", s.robotsTxtHandler)
	mux.HandleFunc("/oembed", s.oembedHandler)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	mux.HandleFunc("/logo", s.logoHandler)
	mux.HandleFunc("/favicon.ico", s.logoHandler)
	// Authentication & Onboarding routes (auth.go)
	mux.HandleFunc("/setup", s.setupHandler)
	mux.HandleFunc("/login", s.loginHandler)
	mux.HandleFunc("/login/2fa", s.login2FAHandler)
	mux.HandleFunc("/reset-password", s.resetPasswordHandler)
	mux.HandleFunc("/forgot-password", s.resetPasswordHandler)
	mux.HandleFunc("/logout", s.logoutHandler)
	mux.HandleFunc("/webauthn/login/begin", s.webAuthnLoginBegin)
	mux.HandleFunc("/webauthn/login/finish", s.webAuthnLoginFinish)
	// File delivery & Management routes (files.go)
	mux.HandleFunc("/f/", s.serveFileHandler)
	mux.HandleFunc("/files", s.requireAuth(s.filesHandler))
	mux.HandleFunc("/edit", s.requireAuth(s.editFileHandler))
	mux.HandleFunc("/delete", s.requireAuth(s.deleteHandler))
	mux.HandleFunc("/api/files/stats", s.requireAuth(s.fileStatsAPIHandler))
	// File Upload routes (upload.go)
	mux.HandleFunc("/upload", s.requireAuth(s.uploadHandler))
	mux.HandleFunc("/api/upload/init", s.requireAuth(s.chunkUploadInitHandler))
	mux.HandleFunc("/api/upload/chunk", s.requireAuth(s.chunkUploadHandler))
	mux.HandleFunc("/api/upload/complete", s.requireAuth(s.chunkUploadCompleteHandler))
	// Settings & User Administration routes (settings.go)
	mux.HandleFunc("/settings", s.requireAuth(s.settingsHandler))
	mux.HandleFunc("/settings/action/", s.requireAuth(s.settingsActionHandler))
	mux.HandleFunc("/settings/appearance", s.requireAuth(s.settingsAppearanceHandler))
	mux.HandleFunc("/settings/appearance/remove_logo", s.requireAuth(s.settingsRemoveLogoHandler))
	mux.HandleFunc("/settings/embed", s.requireAuth(s.settingsEmbedHandler))
	mux.HandleFunc("/settings/storage", s.requireAuth(s.settingsStorageHandler))
	mux.HandleFunc("/settings/subusers", s.requireAuth(s.settingsSubusersHandler))
	mux.HandleFunc("/settings/users/add", s.requireAuth(s.addUserHandler))
	mux.HandleFunc("/settings/users/delete", s.requireAuth(s.deleteUserHandler))
	// Account Security routes - 2FA, WebAuthn passkeys & Recovery Code (security.go)
	mux.HandleFunc("/settings/account", s.requireAuth(s.settingsAccountHandler))
	mux.HandleFunc("/settings/2fa/generate", s.requireAuth(s.totpGenerateHandler))
	mux.HandleFunc("/settings/2fa/verify", s.requireAuth(s.totpVerifyHandler))
	mux.HandleFunc("/settings/2fa/disable", s.requireAuth(s.totpDisableHandler))
	mux.HandleFunc("/settings/recovery/generate", s.requireAuth(s.recoveryGenerateHandler))
	mux.HandleFunc("/settings/recovery/ack", s.requireAuth(s.recoveryAckHandler))
	mux.HandleFunc("/webauthn/register/begin", s.requireAuth(s.webAuthnRegisterBegin))
	mux.HandleFunc("/webauthn/register/finish", s.requireAuth(s.webAuthnRegisterFinish))
	mux.HandleFunc("/settings/webauthn/rename", s.requireAuth(s.webAuthnRenameHandler))
	mux.HandleFunc("/settings/webauthn/delete", s.requireAuth(s.webAuthnDeleteHandler))
	// Main Dashboard route (render.go)
	mux.HandleFunc("/", s.requireAuth(s.dashboardHandler))

	return s.recoveryMiddleware(s.loggingMiddleware(s.indexingProtectionMiddleware(s.requestBodyLimitMiddleware(mux))))
}

// requestBodyLimitMiddleware applies a 1 MB default request body limit to all routes that are not file/chunk upload routes
func (s *Server) requestBodyLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.URL.Path != "/upload" && r.URL.Path != "/api/upload/chunk" && r.URL.Path != "/settings/action/appearance" {
			r.Body = http.MaxBytesReader(w, r.Body, defaultMaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
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
		logger.Info("Server listening on https://localhost:%d", s.cfg.Port)
		return s.httpServer.ListenAndServeTLS(s.cfg.SSLCertPath, s.cfg.SSLKeyPath)
	}
	logger.Info("Server listening on http://localhost:%d", s.cfg.Port)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.stopCh != nil {
		s.stopOnce.Do(func() { close(s.stopCh) })
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) limiter() *authRateLimiter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authLimiter == nil {
		s.authLimiter = newAuthRateLimiter()
	}
	return s.authLimiter
}

// CheckConfigured returns whether an admin account exists in the database
func (s *Server) CheckConfigured(ctx context.Context) (bool, error) {
	if s.configured.Load() {
		return true, nil
	}
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	if database == nil {
		return false, nil
	}
	hasAdmin, err := db.HasAdmin(ctx, database)
	if err != nil {
		return false, err
	}
	if hasAdmin {
		s.configured.Store(true)
		return true, nil
	}
	return false, nil
}

// EnableSetupToken generates and stores a cryptographically random one-time setup token required to complete the setup wizard when starting unconfigured.
func (s *Server) EnableSetupToken() string {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.setupToken == "" {
		s.setupToken = newUploadID()
	}
	return s.setupToken
}

func (s *Server) isConfigured() bool {
	configured, err := s.CheckConfigured(context.Background())
	if err != nil {
		// Fail closed on DB error: do not report "not configured" when the DB is unhealthy.
		return true
	}
	return configured
}

func (s *Server) initDrives(ctx context.Context) {
	s.storageDrives = make(map[string]storage.Provider)
	for _, drive := range s.cfg.Drives {
		p, err := storage.NewProviderFromDrive(ctx, drive)
		if err == nil {
			s.storageDrives[drive.ID] = p
		} else {
			logger.Error("Failed to initialize drive %s: %v", drive.Name, err)
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

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()
	if database != nil {
		if err := database.PingContext(r.Context()); err != nil {
			s.internalError(w, r, "Database health check ping failed", err)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "ok"}`))
}

type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
	wroteHeader  bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.statusCode = code
		rw.wroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.ReverseProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
			return strings.TrimSpace(xrip)
		}
	}
	return r.RemoteAddr
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		defer func() {
			duration := time.Since(start)
			username := ""
			if u := r.Context().Value("username"); u != nil {
				if uname, ok := u.(string); ok {
					username = uname
				}
			}
			if username == "" {
				if cookie, err := r.Cookie("session"); err == nil && cookie.Value != "" {
					if u, ok := s.parseJWTUsername(cookie.Value); ok {
						username = u
					}
				}
			}
			logger.HTTP(r.Method, r.URL.RequestURI(), rw.statusCode, duration, s.clientIP(r), username)
		}()

		next.ServeHTTP(rw, r)
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.internalError(w, r, "PANIC in HTTP handler", fmt.Errorf("%v", rec))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

var allowedPreviewBots = []string{
	"discordbot",
	"twitterbot",
	"telegrambot",
	"slackbot",
	"whatsapp",
	"facebookexternalhit",
	"linkedinbot",
	"viber",
	"skypeuripreview",
	"vkshare",
	"pinterest",
}

var blockedSearchBotTokens = []string{
	"googlebot",
	"adsbot-google",
	"mediapartners-google",
	"googleother",
	"google-extended",
	"bingbot",
	"bingpreview",
	"msnbot",
	"adidxbot",
	"slurp",
	"duckduckbot",
	"duckduckgo",
	"baiduspider",
	"yandexbot",
	"yandeximages",
	"yandex",
	"sogou",
	"exabot",
	"ia_archiver",
	"archive.org_bot",
	"ahrefsbot",
	"semrushbot",
	"mj12bot",
	"dotbot",
	"petalbot",
	"bytespider",
	"gptbot",
	"chatgpt-user",
	"oai-searchbot",
	"claudebot",
	"anthropic-ai",
	"ccbot",
	"perplexitybot",
	"applebot",
	"seznambot",
	"qwantify",
	"blexbot",
	"dataforseobot",
	"rogerbot",
	"screaming frog",
	"amazonbot",
	"youbot",
	"diffbot",
	"cohere-ai",
	"meta-externalagent",
	"facebookbot",
	"searchbot",
	"spider",
	"crawler",
}

// isSearchEngineBot returns true if the User-Agent belongs to a search engine or indexing bot,
// while allowing social/chat link-preview bots (like Discordbot, Twitterbot, TelegramBot).
func isSearchEngineBot(uaStr string) bool {
	if uaStr == "" {
		return false
	}
	ua := strings.ToLower(uaStr)
	for _, allowed := range allowedPreviewBots {
		if strings.Contains(ua, allowed) {
			return false
		}
	}
	for _, token := range blockedSearchBotTokens {
		if strings.Contains(ua, token) {
			return true
		}
	}
	return false
}

func (s *Server) indexingProtectionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		blockIndexing := s.cfg != nil && s.cfg.BlockIndexing
		s.mu.RUnlock()

		if blockIndexing {
			w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet, noimageindex")
			if r.URL.Path != "/robots.txt" && isSearchEngineBot(r.UserAgent()) {
				logger.Debug("Blocked search engine bot from %s (UA: %s)", s.clientIP(r), r.UserAgent())
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) robotsTxtHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	blockIndexing := s.cfg != nil && s.cfg.BlockIndexing
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if blockIndexing {
		w.Write([]byte("User-agent: *\nDisallow: /\n"))
		return
	}
	w.Write([]byte("User-agent: *\nAllow: /\n"))
}

// internalError logs the error to the backend console ONLY and returns a generic "Internal Server Error" to the client.
func (s *Server) internalError(w http.ResponseWriter, r *http.Request, msg string, err error) {
	if err != nil {
		logger.Error("%s: %v", msg, err)
	} else {
		logger.Error("%s", msg)
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") || strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/webauthn/") || strings.HasPrefix(r.URL.Path, "/settings/2fa/generate") || strings.HasPrefix(r.URL.Path, "/settings/webauthn/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal Server Error"}`))
		return
	}
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
