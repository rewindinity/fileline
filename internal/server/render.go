package server

import (
	"net/http"
	"os"
	"path/filepath"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/translations"
)

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
			// If user is logged in, use user's preferred language
			if username := r.Context().Value("username"); username != nil {
				uname := username.(string)
				if user, err := db.GetUserByUsername(r.Context(), s.db, uname); err == nil && user.Language != "" && user.Language != "global" {
					lang = user.Language
				}
				if code, ok := s.recoveryCodeStore.LoadAndDelete(uname); ok {
					m["NewRecoveryCode"] = code
				}
			}
		}
		m["Language"] = lang
		m["Languages"] = translations.AvailableLanguages()
		m["LanguageNames"] = translations.LanguageNames
	}
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		logger.Error("Error rendering template %s: %v", name, err)
	}
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
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	database := s.db
	sanitizedDrives := s.cfg.SanitizedDrives()
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
