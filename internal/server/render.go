package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/translations"
	"fileline/web"
)

const maxPoolBufferSize = 1 << 20 // 1 MiB

var templateBufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, 0, 16<<10))
	},
}

var gzipWriterPool = sync.Pool{
	New: func() any {
		return gzip.NewWriter(io.Discard)
	},
}

func (s *Server) renderTemplate(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	t, ok := s.tmpls[name]
	if !ok {
		s.internalError(w, r, "Template not found: "+name, nil)
		return
	}
	// Inject language into data if it's a map
	if m, ok := data.(map[string]interface{}); ok {
		s.mu.RLock()
		serverCfg := s.cfg
		s.mu.RUnlock()
		switch v := m["Config"].(type) {
		case *config.Config:
			if v != nil {
				m["Config"] = v.SanitizedView()
			} else if serverCfg != nil {
				m["Config"] = serverCfg.SanitizedView()
			} else {
				m["Config"] = config.ConfigView{}
			}
			if user, ok := m["User"].(*db.User); ok && user != nil {
				safeUser := *user
				safeUser.PasswordHash = ""
				safeUser.RecoveryCodeHash = ""
				safeUser.WebAuthnData = ""
				safeUser.SessionVersion = 0
				if user.TOTPSecret != "" {
					safeUser.TOTPSecret = "configured"
				}
				m["User"] = &safeUser
			}
		case config.Config:
			m["Config"] = v.SanitizedView()
		case config.ConfigView:
			// Already sanitized
		case *config.ConfigView:
			if v != nil {
				m["Config"] = *v
			} else {
				m["Config"] = config.ConfigView{}
			}
		default:
			if serverCfg != nil {
				m["Config"] = serverCfg.SanitizedView()
			} else {
				m["Config"] = config.ConfigView{}
			}
		}
		lang := ""
		if serverCfg != nil {
			lang = serverCfg.DefaultLanguage
		}
		if lang == "" {
			lang = "en"
		}
		if r != nil {
			if cookie, err := r.Cookie("lang"); err == nil && cookie.Value != "" {
				lang = cookie.Value
			}
			// If user is logged in, use user's preferred language from cached context user (or map["User"]) without an extra DB query
			var user *db.User
			if u, ok := userFrom(r.Context()); ok {
				user = u
			} else if u, ok := m["User"].(*db.User); ok && u != nil {
				user = u
			}
			uname, _ := usernameFrom(r.Context())
			if user == nil && uname != "" {
				s.mu.RLock()
				database := s.db
				s.mu.RUnlock()
				if database != nil {
					user, _ = db.GetUserByUsername(r.Context(), database, uname)
				}
			}
			if user != nil && user.Language != "" && user.Language != "global" {
				lang = user.Language
			}
			if uname != "" {
				if code, ok := s.recoveryCodeStore.LoadAndDelete(uname); ok {
					m["NewRecoveryCode"] = code
				}
			}
		}
		m["Language"] = lang
		m["Languages"] = translations.AvailableLanguages()
		m["LanguageNames"] = translations.LanguageNames
	}

	buf := templateBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer func() {
		if buf.Cap() <= maxPoolBufferSize {
			buf.Reset()
			templateBufferPool.Put(buf)
		}
	}()

	if err := t.ExecuteTemplate(buf, name, data); err != nil {
		logger.Error("Error rendering template %s: %v", name, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	body := buf.Bytes()

	s.mu.RLock()
	minifyEnabled := s.cfg == nil || s.cfg.MinifyResponses
	gzipEnabled := s.cfg == nil || s.cfg.GzipEnabled
	s.mu.RUnlock()

	if minifyEnabled {
		body = formatHTMLSingleLine(body)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if gzipEnabled && r != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		gz := gzipWriterPool.Get().(*gzip.Writer)
		gz.Reset(w)
		_, _ = gz.Write(body)
		_ = gz.Close()
		gzipWriterPool.Put(gz)
		return
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body)
}

func (s *Server) render404(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	s.renderTemplate(w, nil, "404.html", map[string]interface{}{"Title": "Not Found"})
}

func (s *Server) renderSetupError(w http.ResponseWriter, dbConfigured bool, errorMsg string) {
	s.renderTemplate(w, nil, "setup.html", map[string]interface{}{
		"Title":        "Setup",
		"DBConfigured": dbConfigured,
		"RequireToken": s.setupToken != "",
		"Error":        errorMsg,
	})
}

func (s *Server) dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.mu.RLock()
	database := s.db
	sanitizedDrives := s.cfg.SanitizedDrives()
	s.mu.RUnlock()
	user, err := s.currentUser(r)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	username := user.Username
	filterID := user.ID
	if user.Role == "admin" {
		filterID = 0
	}
	files, err := db.GetRecentFiles(r.Context(), database, 10, filterID)
	if err != nil {
		s.internalError(w, r, "Failed to load recent files for dashboard", err)
		return
	}

	totalUsedBytes, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
	var enabledDrives []config.DriveView
	for _, d := range sanitizedDrives {
		if d.Enabled {
			enabledDrives = append(enabledDrives, d)
		}
	}

	s.renderTemplate(w, r, "dashboard.html", map[string]interface{}{
		"Title":          "Dashboard",
		"Username":       username,
		"User":           user,
		"Files":          files,
		"TotalUsedBytes": totalUsedBytes,
		"EnabledDrives":  enabledDrives,
	})
}

func (s *Server) logoHandler(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	customLogo := s.cfg.CustomLogo
	s.mu.RUnlock()
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'")

	if customLogo == "" || customLogo == "/static/logo.svg" {
		http.ServeFileFS(w, r, web.Static(), "logo.svg")
		return
	}

	cleanLogo := filepath.Base(filepath.Clean(customLogo))
	if cleanLogo == "." || cleanLogo == "/" || strings.Contains(cleanLogo, "..") {
		http.ServeFileFS(w, r, web.Static(), "logo.svg")
		return
	}

	logoPath := filepath.Join("data", cleanLogo)
	if _, err := os.Stat(logoPath); err == nil {
		http.ServeFile(w, r, logoPath)
	} else {
		http.ServeFileFS(w, r, web.Static(), "logo.svg")
	}
}
