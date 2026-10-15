package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"fileline/internal/db"
	"fileline/internal/logger"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mileusna/useragent"
)

// classifyUserAgent categorizes the user-agent string into:
// "bot", "tablet", "mobile", "pc", or "unknown"
func classifyUserAgent(uaStr string) string {
	ua := useragent.Parse(uaStr)
	switch {
	case ua.Bot:
		return "bot"
	case ua.Tablet:
		return "tablet"
	case ua.Mobile:
		return "mobile"
	case ua.Desktop:
		return "pc"
	default:
		return "unknown"
	}
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

	// Record read statistics if enabled
	if f.StatsEnabled && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		uaStr := r.UserAgent()
		devType := classifyUserAgent(uaStr)
		go func(fileID int, dt string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := db.RecordFileRead(ctx, database, fileID, dt); err != nil {
				logger.Error("Failed to record read for file id=%d: %v", fileID, err)
			}
		}(f.ID, devType)
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
	logger.Debug("Serving file: '/f/%s' (id=%d, original_name='%s', size=%s)", urlPath, f.ID, downloadName, logger.FormatBytes(f.Size))
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
		s.internalError(w, r, "Failed to load files from database", err)
		return
	}
	s.renderTemplate(w, r, "files.html", map[string]interface{}{
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
			s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
			return
		}
		var stats *db.FileStats
		if f.StatsEnabled {
			stats, _ = db.GetFileStats(r.Context(), database, f.ID)
		}
		s.renderTemplate(w, r, "edit_file.html", map[string]interface{}{
			"Title":    "Edit File",
			"Username": username,
			"User":     user,
			"File":     f,
			"Stats":    stats,
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
			s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
			return
		}
		customName := r.FormValue("custom_name")
		urlPath := r.FormValue("url_path")
		isPrivate := r.FormValue("is_private") == "on"
		statsEnabled := r.FormValue("stats_enabled") == "on"
		resetStats := r.FormValue("reset_stats") == "1" || r.FormValue("action") == "reset_stats"

		// Reset stats if stats setting changed (activated or deactivated) or manual reset requested
		if statsEnabled != f.StatsEnabled || resetStats {
			if err := db.ResetFileStats(r.Context(), database, id); err != nil {
				logger.Error("Failed to reset stats for file id=%d: %v", id, err)
			} else {
				logger.Action("User '%s' reset statistics for file id=%d (stats_enabled: %t -> %t)", username, id, f.StatsEnabled, statsEnabled)
			}
		}

		if err := db.UpdateFile(r.Context(), database, id, customName, urlPath, isPrivate, statsEnabled); err != nil {
			s.internalError(w, r, "Failed to update file in database", err)
			return
		}
		logger.Action("User '%s' updated file id=%d (custom_name='%s', url_path='%s', private=%t, stats=%t)", username, id, customName, urlPath, isPrivate, statsEnabled)

		if resetStats {
			http.Redirect(w, r, fmt.Sprintf("/edit?id=%d", id), http.StatusFound)
			return
		}
		http.Redirect(w, r, "/files", http.StatusFound)
	}
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
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
		return
	}
	s.mu.RLock()
	st := s.getProvider(f.StorageType)
	s.mu.RUnlock()
	if err := st.Delete(r.Context(), f.StoragePath); err != nil {
		logger.Error("Failed to delete file from storage: %v", err)
	}
	if err := db.DeleteFile(r.Context(), database, id); err != nil {
		s.internalError(w, r, "Failed to delete file from database", err)
		return
	}
	logger.Action("User '%s' deleted file id=%d ('%s')", username, id, f.OriginalName)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) fileStatsAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var id int
	fmt.Sscanf(r.URL.Query().Get("id"), "%d", &id)
	if id <= 0 {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

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
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var stats *db.FileStats
	if f.StatsEnabled {
		stats, err = db.GetFileStats(r.Context(), database, f.ID)
		if err != nil {
			s.internalError(w, r, "Failed to load file stats", err)
			return
		}
	} else {
		stats = &db.FileStats{}
	}

	displayName := f.OriginalName
	if f.CustomName != "" {
		displayName = f.CustomName
	}

	lastReadFormatted := ""
	if stats.LastReadAt != nil {
		lastReadFormatted = stats.LastReadAt.Format("Jan 02, 2006 15:04")
	}

	res := map[string]interface{}{
		"id":                  f.ID,
		"name":                displayName,
		"url_path":            f.URLPath,
		"stats_enabled":       f.StatsEnabled,
		"total_reads":         stats.TotalReads,
		"reads_24h":           stats.Reads24h,
		"last_read_at":        stats.LastReadAt,
		"last_read_formatted": lastReadFormatted,
		"mobile":              stats.Mobile,
		"pc":                  stats.PC,
		"tablet":              stats.Tablet,
		"bots":                stats.Bots,
		"unknown":             stats.Unknown,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

