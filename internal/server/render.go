package server

import (
	"log"
	"net/http"
	"os"
	"path/filepath"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/translations"
)

func (s *Server) renderTemplate(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	t, ok := s.tmpls[name]
	if !ok {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		log.Printf("Template not found: %s", name)
		return
	}
	// Inject language into data if it's a map
	if m, ok := data.(map[string]interface{}); ok {
		lang := s.cfg.DefaultLanguage
		if lang == "" {
			lang = "en"
		}
		if r != nil {
			if cookie, err := r.Cookie("lang"); err == nil && cookie.Value != "" {
				lang = cookie.Value
			}
			// If user is logged in, use user's preferred language
			if username := r.Context().Value("username"); username != nil {
				if user, err := db.GetUserByUsername(r.Context(), s.db, username.(string)); err == nil && user.Language != "" && user.Language != "global" {
					lang = user.Language
				}
			}
		}
		m["Language"] = lang
		m["Languages"] = translations.AvailableLanguages()
		m["LanguageNames"] = translations.LanguageNames
	}
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("Error rendering template %s: %v", name, err)
	}
}

func (s *Server) render404(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	s.renderTemplate(w, nil, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
}

func (s *Server) renderSetupError(w http.ResponseWriter, dbConfigured bool, errorMsg string) {
	s.renderTemplate(w, nil, "setup.html", map[string]interface{}{
		"Title":        "Setup",
		"Config":       s.cfg,
		"DBConfigured": dbConfigured,
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

	s.renderTemplate(w, r, "dashboard.html", map[string]interface{}{
		"Title":          "Dashboard",
		"Username":       username,
		"User":           user,
		"Files":          files,
		"TotalUsedBytes": totalUsedBytes,
		"Config":         s.cfg,
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
