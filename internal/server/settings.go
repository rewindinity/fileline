package server

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/storage"

	"golang.org/x/crypto/bcrypt"
)

func (s *Server) settingsHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()

	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	user, _ := db.GetUserByUsername(r.Context(), database, username)

	passkeysDisplay := formatPasskeysDisplay(user.WebAuthnData)

	var allUsers []*db.User
	if user.Role == "admin" {
		allUsers, _ = db.GetAllUsers(r.Context(), database)
	}
	drivesJSONBytes, _ := json.MarshalIndent(cfg.Drives, "", "  ")
	if string(drivesJSONBytes) == "null" {
		drivesJSONBytes = []byte("[]")
	}
	s.renderTemplate(w, r, "settings.html", map[string]interface{}{
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

func (s *Server) settingsAppearanceHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	s.mu.RLock()
	cfg := s.cfg
	database := s.db
	s.mu.RUnlock()
	user, _ := db.GetUserByUsername(r.Context(), database, username)
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, r, "settings_appearance.html", map[string]interface{}{
		"Title":          "Appearance Settings",
		"Username":       username,
		"User":           user,
		"Config":         cfg,
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
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
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
		return
	}
	drivesJSONBytes, _ := json.MarshalIndent(cfg.Drives, "", "  ")
	if string(drivesJSONBytes) == "null" {
		drivesJSONBytes = []byte("[]")
	}
	successMsg := r.URL.Query().Get("success")
	errorMsg := r.URL.Query().Get("error")
	s.renderTemplate(w, r, "settings_storage.html", map[string]interface{}{
		"Title":          "Storage Settings",
		"Username":       username,
		"User":           user,
		"Config":         cfg,
		"DrivesJSON":     string(drivesJSONBytes),
		"EnvOnly":        cfg.EnvOnly,
		"SuccessMessage": successMsg,
		"ErrorMessage":   errorMsg,
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
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
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
	s.renderTemplate(w, r, "settings_subusers.html", map[string]interface{}{
		"Title":          "Subusers Settings",
		"Username":       username,
		"User":           user,
		"Config":         cfg,
		"AllUsers":       displayUsers,
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
	action := strings.TrimPrefix(r.URL.Path, "/settings/action/")

	if action == "storage" {
		s.mu.RLock()
		database := s.db
		s.mu.RUnlock()
		user, _ := db.GetUserByUsername(r.Context(), database, username)
		if user.Role != "admin" {
			s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
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
		switch storageType {
		case "local":
			localPath := r.FormValue("local_path")
			if localPath == "" {
				localPath = "./uploads"
			}
			s.cfg.LocalStoragePath = localPath
		case "s3":
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
		language := r.FormValue("language")
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
		if language == "" {
			language = "global"
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
		err = db.UpdateUserLanguage(r.Context(), database, username, language)
		if err != nil {
			http.Redirect(w, r, "/settings/appearance?error=Failed+to+update+language", http.StatusFound)
			return
		}
		if user.Role == "admin" {
			globalTheme := r.FormValue("global_theme")
			customAccentHex := r.FormValue("custom_accent_hex")
			globalLanguage := r.FormValue("global_language")
			s.mu.Lock()
			if globalTheme != "" {
				s.cfg.Theme = globalTheme
			}
			if customAccentHex != "" {
				s.cfg.CustomAccentHex = customAccentHex
			}
			if globalLanguage != "" {
				s.cfg.DefaultLanguage = globalLanguage
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
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
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
		s.renderTemplate(w, r, "404.html", map[string]interface{}{"Title": "Not Found", "Config": s.cfg})
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
