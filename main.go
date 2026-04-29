package main

import (
	"crypto/tls"
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"fileline/auth"
	"fileline/database"
	"fileline/handlers"
	"fileline/models"
	i18n "fileline/translations"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

/**
  formatSize converts a byte count into a human-friendly unit string.
  @param bytes - The size in bytes.
  @returns string - The resulting string value.
*/
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

/**
  formatDate parses RFC3339 timestamps and renders a stable UI date/time format.
  @param dateStr - The date string to format.
  @returns string - The resulting string value.
*/
func formatDate(dateStr string) string {
	t, err := time.Parse(time.RFC3339, dateStr)
	if err != nil {
		return dateStr
	}
	return t.Format("2006/01/02 15:04")
}

/**
  truncate applies rune-safe truncation for UI previews.
  @param s - The source string.
  @param max - The maximum allowed length.
  @returns string - The resulting string value.
*/
func truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max]) + "..."
}

/**
  normalizeConfiguredHost processes the user-provided domain/host configuration, stripping schemes, paths, and extraneous entries to derive a clean host value for WebAuthn RP configuration.
  @param raw - The raw domain/host configuration string.
  @returns string - The normalized host value.
*/
func normalizeConfiguredHost(raw string) string {
	host := strings.TrimSpace(strings.Split(raw, ",")[0])
	if host == "" {
		return ""
	}
	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
			host = parsed.Host
		}
	}
	host = strings.TrimSpace(strings.Split(host, "/")[0])
	return host
}

/**
  hostWithoutPort removes any port information from a host string, handling IPv6 formats correctly.
  @param host - The input host string, potentially containing a port.
  @returns string - The host string without any port information.
*/
func hostWithoutPort(host string) string {
	if host == "" {
		return ""
	}
	trimmed := host
	if strings.Contains(trimmed, ":") {
		if h, _, err := net.SplitHostPort(trimmed); err == nil {
			trimmed = h
		}
	}
	return strings.Trim(trimmed, "[]")
}

/**
  deriveWebAuthnRPConfig computes the relying party ID and origin for WebAuthn based on the application's domain configuration, applying normalization and sensible defaults to ensure compatibility across various deployment scenarios.
  @param none - This function does not accept parameters.
  @returns (string, string) - The derived RP ID and origin URL for WebAuthn configuration.
*/
func deriveWebAuthnRPConfig() (string, string) {
	host := normalizeConfiguredHost(database.Config.Domain)
	scheme := "http"
	if database.Config.SSLEnabled {
		scheme = "https"
	}
	if host == "" {
		if database.Config.Port == 80 || database.Config.Port == 443 {
			host = "localhost"
		} else {
			host = fmt.Sprintf("localhost:%d", database.Config.Port)
		}
	}
	return hostWithoutPort(host), scheme + "://" + host
}

type filteredHTTPErrorWriter struct{}

/**
  Write filters out specific non-critical HTTP/2 GOAWAY errors to prevent log pollution, while allowing all other error messages to be logged as usual.
  @param p - The byte slice containing the log message.
  @returns (int, error) - The number of bytes written and any error encountered during writing.
*/
func (w filteredHTTPErrorWriter) Write(p []byte) (int, error) {
	line := string(p)
	if strings.Contains(line, "http2: received GOAWAY") {
		return len(p), nil
	}
	return os.Stderr.Write(p)
}

func newHTTPErrorLogger() *log.Logger {
	return log.New(filteredHTTPErrorWriter{}, "http: ", log.LstdFlags)
}

func applySecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline' https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; font-src 'self' https://fonts.gstatic.com https://unpkg.com data:; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
	)
}

type statusTrackingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusTrackingResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusTrackingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func parseDebugFlag() bool {
	debugEnabled := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()
	return *debugEnabled
}

/**
  withPanicRecovery wraps an HTTP handler to recover from panics, log the error and stack trace, and return a generic 500 error response to the client.
  @param next - The HTTP handler to wrap.
  @returns http.Handler - The wrapped HTTP handler with panic recovery.
*/
func withPanicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Printf("PANIC: %s %s: %v\n%s", r.Method, r.URL.Path, recovered, string(debug.Stack()))
				handlers.RenderHTTPError(w, r, http.StatusInternalServerError, "Unexpected server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

/**
  withRequestLogging wraps an HTTP handler to log incoming requests and their response status, while ignoring 404 errors to reduce noise. Debug logging can be toggled with the debugEnabled parameter.
  @param next - The HTTP handler to wrap.
  @param debugEnabled - A boolean flag to enable or disable debug logging.
  @returns http.Handler - The wrapped HTTP handler with request logging.
*/
func withRequestLogging(next http.Handler, debugEnabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		recorder := &statusTrackingResponseWriter{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		duration := time.Since(startedAt).Round(time.Millisecond)
		if status == http.StatusNotFound {
			return
		}
		if status >= http.StatusBadRequest {
			log.Printf("HTTP %d %s %s (%s)", status, r.Method, r.URL.Path, duration)
			return
		}
		if debugEnabled {
			handlers.Debugf("%d %s %s (%s)", status, r.Method, r.URL.Path, duration)
		}
	})
}

/**
  main initializes shared services, registers routes, and starts the web server.
  @param none - This function does not accept parameters.
  @returns void
*/
func main() {
	debugEnabled := parseDebugFlag()
	auth.SetDebug(debugEnabled)
	database.SetDebug(debugEnabled)
	handlers.SetDebug(debugEnabled)
	if debugEnabled {
		log.Printf("Debug mode enabled")
	}
	// Load translations
	if err := i18n.Load(); err != nil {
		log.Printf("Warning: Failed to load translations: %v", err)
	}
	// Load or create config
	if err := database.LoadConfig(); err != nil {
		log.Printf("Creating default config: %v", err)
		database.InitConfigDefaults()
	}
	// Only initialize database if configured (setup has been completed)
	// During initial setup, the database will be initialized by HandleSetup
	if database.Config.DatabaseType != "" {
		if err := database.InitDatabase(); err != nil {
			log.Printf("Failed to connect to database: %v", err)
			// Only create defaults if it's a file-not-found error for SQLite.
			if database.Config.DatabaseType == "sqlite" {
				// Check if it's just a missing file (not a connection error)
				if os.IsNotExist(err) {
					database.InitDefaults()
				} else {
					log.Fatalf("Failed to connect to database: %v", err)
				}
			} else {
				// For MongoDB/PostgreSQL, connection errors are fatal
				log.Printf("Failed to connect to database")
			}
		}
	}
	// Ensure directories exist
	os.MkdirAll(models.UploadsDir, 0755)
	os.MkdirAll(models.ChunksDir, 0755)
	// Start anti-brute-force cleanup routine
	auth.StartCleanupRoutine()
	auth.StartUploadLimiterCleanupRoutine()
	// Initialize WebAuthn with a normalized RP configuration.
	rpID, rpOrigin := deriveWebAuthnRPConfig()
	if err := handlers.InitWebAuthn("FileLine", rpID, rpOrigin); err != nil {
		log.Printf("Warning: WebAuthn initialization failed: %v", err)
	}
	// Parse templates once at startup and attach helper funcs for consistent rendering.
	var err error
	handlers.Templates, err = template.New("").Funcs(template.FuncMap{
		"formatSize": formatSize,
		"formatDate": formatDate,
		"truncate":   truncate,
		"divide":     func(a, b int64) int64 { return a / b },
		"safeURL":    func(s string) template.URL { return template.URL(s) },
	}).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		log.Fatal("Failed to parse templates:", err)
	}
	// Register application routes on a dedicated mux.
	mux := http.NewServeMux()
	// Static files from embedded FS
	staticContent, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticContent))))
	// Public and authenticated endpoints.
	mux.HandleFunc("/", handlers.HandleHome)
	mux.HandleFunc("/setup", handlers.HandleSetup)
	mux.HandleFunc("/login", handlers.HandleLogin)
	mux.HandleFunc("/login/2fa", handlers.Handle2FAVerify)
	mux.HandleFunc("/reset-password", handlers.HandleResetPassword)
	mux.HandleFunc("/logout", handlers.HandleLogout)
	mux.HandleFunc("/upload", handlers.HandleUpload)
	mux.HandleFunc("/files", handlers.HandleFiles)
	mux.HandleFunc("/file/edit/", handlers.HandleFileEdit)
	mux.HandleFunc("/file/delete/", handlers.HandleFileDelete)
	mux.HandleFunc("/f/", handlers.HandleFileAccess)
	mux.HandleFunc("/api/stats", handlers.HandleStats)
	mux.HandleFunc("/api/settings", handlers.HandleAPISettings)
	mux.HandleFunc("/settings", handlers.HandleSettings)
	mux.HandleFunc("/settings/password", handlers.HandlePasswordChange)
	mux.HandleFunc("/settings/2fa", handlers.Handle2FASettings)
	mux.HandleFunc("/settings/2fa/setup", handlers.Handle2FASetup)
	mux.HandleFunc("/settings/2fa/disable", handlers.Handle2FADisable)
	mux.HandleFunc("/settings/theme", handlers.HandleThemeSettings)
	mux.HandleFunc("/settings/language", handlers.HandleLanguageSettings)
	mux.HandleFunc("/settings/upload", handlers.HandleUploadSettings)
	mux.HandleFunc("/settings/storage", handlers.HandleStorageDrivesSettings)
	mux.HandleFunc("/settings/backup-code", handlers.HandleBackupCodeRegenerate)
	mux.HandleFunc("/settings/passkey/register/begin", handlers.HandlePasskeyRegistrationBegin)
	mux.HandleFunc("/settings/passkey/register/finish", handlers.HandlePasskeyRegistrationFinish)
	mux.HandleFunc("/settings/passkey/list", handlers.HandlePasskeyList)
	mux.HandleFunc("/settings/passkey/delete", handlers.HandlePasskeyDelete)
	mux.HandleFunc("/api/passkey/auth/begin", handlers.HandlePasskeyAuthBegin)
	mux.HandleFunc("/api/passkey/auth/finish", handlers.HandlePasskeyAuthFinish)
	mux.HandleFunc("/api/upload/init", handlers.HandleChunkInit)
	mux.HandleFunc("/api/upload/chunk", handlers.HandleChunkUpload)
	mux.HandleFunc("/api/upload/complete", handlers.HandleChunkComplete)
	// protectedHandler applies global guards before routing to specific handlers.
	protectedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w)

		// Keep static assets reachable so the 403 page can render correctly.
		if strings.HasPrefix(r.URL.Path, "/static/") {
			mux.ServeHTTP(w, r)
			return
		}
		// For external databases, probe configuration status to surface connection loss quickly.
		if database.Config.DatabaseType == "mongodb" || database.Config.DatabaseType == "postgresql" {
			_ = database.IsConfigured()
		}
		if database.HasConnectionError() {
			handlers.RenderHTTPError(w, r, http.StatusInternalServerError, "Failed to connect to database")
			return
		}
		if auth.IsIPBanned(r, database.Config.IsBehindProxy) {
			handlers.RenderHTTPError(w, r, http.StatusForbidden, "Too many failed attempts. Access temporarily denied.")
			return
		}
		mux.ServeHTTP(w, r)
	})
	serverHandler := withRequestLogging(withPanicRecovery(protectedHandler), debugEnabled)
	addr := fmt.Sprintf(":%d", database.Config.Port)
	if database.Config.SSLEnabled && database.Config.CertBase64 != "" && database.Config.KeyBase64 != "" {
		// Decode certificates
		certPEM, err := base64.StdEncoding.DecodeString(database.Config.CertBase64)
		if err != nil {
			log.Fatal("Failed to decode certificate:", err)
		}
		keyPEM, err := base64.StdEncoding.DecodeString(database.Config.KeyBase64)
		if err != nil {
			log.Fatal("Failed to decode private key:", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			log.Fatal("Failed to load certificate:", err)
		}
		server := &http.Server{
			Addr:     addr,
			Handler:  serverHandler,
			ErrorLog: newHTTPErrorLogger(),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		}
		log.Printf("Starting HTTPS server on %s", addr)
		log.Fatal(server.ListenAndServeTLS("", ""))
	} else {
		server := &http.Server{
			Addr:     addr,
			Handler:  serverHandler,
			ErrorLog: newHTTPErrorLogger(),
		}
		log.Printf("Starting HTTP server on %s", addr)
		log.Fatal(server.ListenAndServe())
	}
}
