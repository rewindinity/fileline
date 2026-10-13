package server

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"fileline/internal/db"
	"fileline/internal/logger"

	"github.com/golang-jwt/jwt/v5"
)

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
		s.renderTemplate(w, r, "edit_file.html", map[string]interface{}{
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
			s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
			return
		}
		customName := r.FormValue("custom_name")
		urlPath := r.FormValue("url_path")
		isPrivate := r.FormValue("is_private") == "on"
		if err := db.UpdateFile(r.Context(), database, id, customName, urlPath, isPrivate); err != nil {
			s.internalError(w, r, "Failed to update file in database", err)
			return
		}
		logger.Action("User '%s' updated file id=%d (custom_name='%s', url_path='%s', private=%t)", username, id, customName, urlPath, isPrivate)
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
