package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"fileline/internal/db"
	"fileline/internal/logger"
	"fileline/internal/storage"
)

type ScannedFileView struct {
	DriveID       string `json:"drive_id"`
	DriveName     string `json:"drive_name"`
	DriveType     string `json:"drive_type"`
	Key           string `json:"key"`
	Size          int64  `json:"size"`
	FormattedSize string `json:"formatted_size"`
}

type scanDriveTarget struct {
	id       string
	name     string
	typeName string
	provider storage.Provider
}

func (s *Server) getScanTargets(requestedDriveID string) []scanDriveTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var targets []scanDriveTarget
	if s.cfg == nil {
		if s.storage != nil {
			targets = append(targets, scanDriveTarget{
				id:       "default",
				name:     "Default Storage",
				typeName: "local",
				provider: s.storage,
			})
		}
		return targets
	}

	if len(s.cfg.Drives) == 0 {
		if s.storage != nil {
			targets = append(targets, scanDriveTarget{
				id:       "default",
				name:     "Default Storage",
				typeName: s.cfg.StorageType,
				provider: s.storage,
			})
		}
		return targets
	}

	for _, d := range s.cfg.Drives {
		if !d.Enabled {
			continue
		}
		if requestedDriveID != "" && requestedDriveID != "all" && d.ID != requestedDriveID {
			continue
		}
		p, ok := s.storageDrives[d.ID]
		if !ok || p == nil {
			continue
		}
		targets = append(targets, scanDriveTarget{
			id:       d.ID,
			name:     d.Name,
			typeName: d.Type,
			provider: p,
		})
	}
	return targets
}

func (s *Server) adminScanStorageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := s.currentUser(r)
	if err != nil || user == nil || user.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	driveID := strings.TrimSpace(r.URL.Query().Get("drive_id"))
	targets := s.getScanTargets(driveID)

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	knownPaths, err := db.GetAllStoragePaths(r.Context(), database)
	if err != nil {
		logger.Error("Failed to fetch storage paths during storage scan: %v", err)
		http.Error(w, "Failed to inspect database records", http.StatusInternalServerError)
		return
	}

	var scannedFiles []ScannedFileView
	for _, target := range targets {
		lp, ok := target.provider.(storage.ListableProvider)
		if !ok {
			continue
		}
		items, err := lp.List(r.Context())
		if err != nil {
			logger.Error("Failed to list items for drive %s (%s): %v", target.id, target.name, err)
			continue
		}
		for _, it := range items {
			if it.Key == "" || strings.HasPrefix(it.Key, ".") {
				continue
			}
			if knownPaths[it.Key] {
				continue
			}
			scannedFiles = append(scannedFiles, ScannedFileView{
				DriveID:       target.id,
				DriveName:     target.name,
				DriveType:     target.typeName,
				Key:           it.Key,
				Size:          it.Size,
				FormattedSize: logger.FormatBytes(it.Size),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"files":   scannedFiles,
	})
}

type importFileEntry struct {
	DriveID string `json:"drive_id"`
	Key     string `json:"key"`
}

type importRequest struct {
	Files []importFileEntry `json:"files"`
}

type importResponse struct {
	Success  bool     `json:"success"`
	Imported int      `json:"imported"`
	Failed   int      `json:"failed"`
	Errors   []string `json:"errors,omitempty"`
}

func (s *Server) adminImportStorageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	user, err := s.currentUser(r)
	if err != nil || user == nil || user.Role != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req importRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if len(req.Files) == 0 {
		http.Error(w, "No files specified for import", http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	database := s.db
	s.mu.RUnlock()

	knownPaths, err := db.GetAllStoragePaths(r.Context(), database)
	if err != nil {
		logger.Error("Failed to fetch storage paths during import: %v", err)
		http.Error(w, "Failed to inspect database records", http.StatusInternalServerError)
		return
	}

	var importedCount, failedCount int
	var errMessages []string

	for _, entry := range req.Files {
		entry.Key = strings.TrimSpace(entry.Key)
		if entry.Key == "" || strings.HasPrefix(entry.Key, ".") {
			failedCount++
			errMessages = append(errMessages, fmt.Sprintf("invalid file name: %q", entry.Key))
			continue
		}
		if knownPaths[entry.Key] {
			failedCount++
			errMessages = append(errMessages, fmt.Sprintf("file %q already imported", entry.Key))
			continue
		}

		prov, actualDriveID, err := s.getUploadProvider(entry.DriveID)
		if err != nil {
			failedCount++
			errMessages = append(errMessages, fmt.Sprintf("drive error for %q: %v", entry.Key, err))
			continue
		}

		lp, ok := prov.(storage.ListableProvider)
		if !ok {
			failedCount++
			errMessages = append(errMessages, fmt.Sprintf("storage provider for %q does not support import operations", entry.Key))
			continue
		}

		// Generate random, collision-safe storage key
		storageKey := newStorageKey()

		// Rename object from original key to internal storage key
		if err := lp.Rename(r.Context(), entry.Key, storageKey); err != nil {
			failedCount++
			errMessages = append(errMessages, fmt.Sprintf("failed to rename %q on storage: %v", entry.Key, err))
			continue
		}

		// Determine file size
		var actualSize int64
		if sp, ok := prov.(storage.SeekableProvider); ok {
			if fObj, err := sp.Open(r.Context(), storageKey); err == nil {
				if statter, ok := fObj.(interface{ Stat() (os.FileInfo, error) }); ok {
					if fi, err := statter.Stat(); err == nil {
						actualSize = fi.Size()
					}
				}
				_ = fObj.Close()
			}
		} else if rp, ok := prov.(storage.RangeProvider); ok {
			if headObj, err := rp.Head(r.Context(), storageKey); err == nil {
				actualSize = headObj.ContentLength
			}
		}
		if actualSize == 0 {
			if rc, err := prov.Get(r.Context(), storageKey); err == nil {
				n, _ := io.Copy(io.Discard, rc)
				_ = rc.Close()
				actualSize = n
			}
		}

		// Enforce user storage quota if configured
		if user.StorageQuotaMB > 0 {
			currentUsed, _ := db.GetUserTotalStorage(r.Context(), database, user.ID)
			if currentUsed+actualSize > int64(user.StorageQuotaMB)*1024*1024 {
				// Rollback rename
				_ = lp.Rename(r.Context(), storageKey, entry.Key)
				failedCount++
				errMessages = append(errMessages, fmt.Sprintf("quota exceeded for file %q", entry.Key))
				continue
			}
		}

		// Slugify URLPath with collision resolution
		urlPath := slugifyURLPath(entry.Key)
		if err := validateURLPath(urlPath); err != nil {
			urlPath = slugifyURLPath("file")
		}

		fileRecord := &db.File{
			OriginalName: entry.Key,
			CustomName:   "",
			URLPath:      urlPath,
			Size:         actualSize,
			IsPrivate:    false,
			StorageType:  actualDriveID,
			StoragePath:  storageKey,
			UserID:       user.ID,
			StatsEnabled: true,
		}

		var insertErr error
		for attempt := 0; attempt < 5; attempt++ {
			insertErr = db.InsertFile(r.Context(), database, fileRecord)
			if insertErr == nil {
				break
			}
			fileRecord.URLPath = appendRandomURLPathSuffix(urlPath)
		}

		if insertErr != nil {
			// Rollback rename on DB failure
			_ = lp.Rename(r.Context(), storageKey, entry.Key)
			failedCount++
			errMessages = append(errMessages, fmt.Sprintf("database error for %q: %v", entry.Key, insertErr))
			continue
		}

		knownPaths[storageKey] = true
		importedCount++
		logger.Action("Admin '%s' imported file '%s' (size: %s, storage: %s, path: %s)",
			user.Username, entry.Key, logger.FormatBytes(actualSize), actualDriveID, storageKey)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(importResponse{
		Success:  importedCount > 0 || failedCount == 0,
		Imported: importedCount,
		Failed:   failedCount,
		Errors:   errMessages,
	})
}
