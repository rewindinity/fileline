package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	_ "github.com/mattn/go-sqlite3"

	"fileline/models"
)

// SQLiteDB implements DatabaseInterface on top of local SQLite storage.
type SQLiteDB struct {
	db *sql.DB
}

/**
  Load opens SQLite storage and ensures required tables exist.
  @param none - This function does not accept parameters.
  @returns error - An error if the operation fails.
*/
func (s *SQLiteDB) Load() error {
	var err error
	s.db, err = sql.Open("sqlite3", models.DBFileSQLite)
	if err != nil {
		return err
	}
	// Create tables if they don't exist
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS users (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			created_at TEXT NOT NULL,
			two_fa_enabled INTEGER DEFAULT 0,
			two_fa_secret TEXT,
			backup_code TEXT,
			passkeys TEXT
		);

		CREATE TABLE IF NOT EXISTS files (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			link TEXT UNIQUE NOT NULL,
			size INTEGER NOT NULL,
			uploaded_at TEXT NOT NULL,
			is_private INTEGER NOT NULL
		);

		CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS chunk_uploads (
			id TEXT PRIMARY KEY,
			file_name TEXT NOT NULL,
			total_size INTEGER NOT NULL,
			total_chunks INTEGER NOT NULL,
			received TEXT NOT NULL,
			is_private INTEGER NOT NULL,
			custom_link TEXT NOT NULL,
			temp_dir TEXT NOT NULL,
			created_at TEXT NOT NULL
		);
	`)
	return err
}

/**
  Save is a no-op for SQLite (auto-committed).
  @param none - This function does not accept parameters.
  @returns error - An error if the operation fails.
*/
func (s *SQLiteDB) Save() error {
	return nil
}

/**
  InitDefaults seeds first-run defaults for setup state and UI settings.
  @param none - This function does not accept parameters.
  @returns void
*/
func (s *SQLiteDB) InitDefaults() {
	s.SetConfigured(false)
	settings := models.AppSettings{
		Theme:          "dark-blue",
		AccentColor:    "#3b82f6",
		Language:       "en",
		ChunkSizeBytes: models.DefaultChunkSize,
		ChunkThreshold: models.DefaultChunkThreshold,
		MaxFileSize:    0,
	}
	s.UpdateSettings(settings)
}

/**
  IsConfigured returns whether the database is configured.
  @param none - This function does not accept parameters.
  @returns bool - True when is configured is satisfied; otherwise false.
*/
func (s *SQLiteDB) IsConfigured() bool {
	var value string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = 'configured'").Scan(&value)
	if err != nil {
		return false
	}
	return value == "true"
}

/**
  SetConfigured persists setup completion state.
  @param configured - Whether initial setup is complete.
  @returns void
*/
func (s *SQLiteDB) SetConfigured(configured bool) {
	value := "false"
	if configured {
		value = "true"
	}
	s.db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ('configured', ?)", value)
}

/**
  GetUser returns the user.
  @param none - This function does not accept parameters.
  @returns *models.User - The matching value, or nil when not found.
*/
func (s *SQLiteDB) GetUser() *models.User {
	var user models.User
	var twoFAEnabled int
	var passkeysJSON string
	err := s.db.QueryRow("SELECT username, password_hash, created_at, two_fa_enabled, COALESCE(two_fa_secret, ''), COALESCE(backup_code, ''), COALESCE(passkeys, '[]') FROM users LIMIT 1").
		Scan(&user.Username, &user.PasswordHash, &user.CreatedAt, &twoFAEnabled, &user.TwoFASecret, &user.BackupCode, &passkeysJSON)
	if err != nil {
		return nil
	}
	user.TwoFAEnabled = twoFAEnabled == 1
	// Deserialize passkeys
	if passkeysJSON != "" && passkeysJSON != "[]" {
		json.Unmarshal([]byte(passkeysJSON), &user.Passkeys)
	}
	return &user
}

/**
  SetUser replaces the single user row expected by this application.
  @param user - The user record to persist.
  @returns void
*/
func (s *SQLiteDB) SetUser(user *models.User) {
	twoFAEnabled := 0
	if user.TwoFAEnabled {
		twoFAEnabled = 1
	}
	// Serialize passkeys to JSON so credentials remain backend-agnostic.
	passkeysJSON, _ := json.Marshal(user.Passkeys)
	s.db.Exec("DELETE FROM users")
	s.db.Exec("INSERT INTO users (username, password_hash, created_at, two_fa_enabled, two_fa_secret, backup_code, passkeys) VALUES (?, ?, ?, ?, ?, ?, ?)",
		user.Username, user.PasswordHash, user.CreatedAt, twoFAEnabled, user.TwoFASecret, user.BackupCode, string(passkeysJSON))
}

/**
  GetFiles returns all files.
  @param none - This function does not accept parameters.
  @returns []models.FileEntry - The resulting collection.
*/
func (s *SQLiteDB) GetFiles() []models.FileEntry {
	rows, err := s.db.Query("SELECT id, name, link, size, uploaded_at, is_private FROM files ORDER BY uploaded_at DESC")
	if err != nil {
		return []models.FileEntry{}
	}
	defer rows.Close()
	var files []models.FileEntry
	for rows.Next() {
		var f models.FileEntry
		var isPrivate int
		rows.Scan(&f.ID, &f.Name, &f.Link, &f.Size, &f.UploadedAt, &isPrivate)
		f.IsPrivate = isPrivate == 1
		files = append(files, f)
	}
	return files
}

/**
  GetFileByID returns a file entry by ID.
  @param id - The identifier to process.
  @returns *models.FileEntry - The matching value, or nil when not found.
*/
func (s *SQLiteDB) GetFileByID(id string) *models.FileEntry {
	var f models.FileEntry
	var isPrivate int
	err := s.db.QueryRow("SELECT id, name, link, size, uploaded_at, is_private FROM files WHERE id = ?", id).
		Scan(&f.ID, &f.Name, &f.Link, &f.Size, &f.UploadedAt, &isPrivate)
	if err != nil {
		return nil
	}
	f.IsPrivate = isPrivate == 1
	return &f
}

/**
  GetFileByLink returns a file entry by link.
  @param link - The public link value.
  @returns *models.FileEntry - The matching value, or nil when not found.
*/
func (s *SQLiteDB) GetFileByLink(link string) *models.FileEntry {
	var f models.FileEntry
	var isPrivate int
	err := s.db.QueryRow("SELECT id, name, link, size, uploaded_at, is_private FROM files WHERE link = ?", link).
		Scan(&f.ID, &f.Name, &f.Link, &f.Size, &f.UploadedAt, &isPrivate)
	if err != nil {
		return nil
	}
	f.IsPrivate = isPrivate == 1
	return &f
}

/**
  LinkExists checks if a link already exists.
  @param link - The public link value.
  @returns bool - True when link exists is satisfied; otherwise false.
*/
func (s *SQLiteDB) LinkExists(link string) bool {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM files WHERE link = ?", link).Scan(&count)
	return count > 0
}

/**
  AddFile inserts a new file metadata row.
  @param file - The file entry to store.
  @returns error - An error if the operation fails.
*/
func (s *SQLiteDB) AddFile(file models.FileEntry) error {
	isPrivate := 0
	if file.IsPrivate {
		isPrivate = 1
	}
	_, err := s.db.Exec("INSERT INTO files (id, name, link, size, uploaded_at, is_private) VALUES (?, ?, ?, ?, ?, ?)",
		file.ID, file.Name, file.Link, file.Size, file.UploadedAt, isPrivate)
	return err
}

/**
  UpdateFile updates an existing file entry.
  @param id - The identifier to process.
  @param name - The file name.
  @param link - The public link value.
  @param isPrivate - Whether the file should be private.
  @returns error - An error if the operation fails.
*/
func (s *SQLiteDB) UpdateFile(id string, name, link string, isPrivate bool) error {
	isPrivateInt := 0
	if isPrivate {
		isPrivateInt = 1
	}
	result, err := s.db.Exec("UPDATE files SET name = ?, link = ?, is_private = ? WHERE id = ?", name, link, isPrivateInt, id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("file not found")
	}
	return nil
}

/**
  DeleteFile removes a file entry by ID.
  @param id - The identifier to process.
  @returns error - An error if the operation fails.
*/
func (s *SQLiteDB) DeleteFile(id string) error {
	result, err := s.db.Exec("DELETE FROM files WHERE id = ?", id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("file not found")
	}
	return nil
}

/**
  GetSettings returns the settings.
  @param none - This function does not accept parameters.
  @returns models.AppSettings - The resulting value.
*/
func (s *SQLiteDB) GetSettings() models.AppSettings {
	// Start with defaults so partially-populated settings rows remain safe.
	settings := models.AppSettings{
		Theme:          "dark-blue",
		AccentColor:    "#3b82f6",
		Language:       "en",
		ChunkSizeBytes: models.DefaultChunkSize,
		ChunkThreshold: models.DefaultChunkThreshold,
		MaxFileSize:    0,
		CustomLogo:     "",
	}
	var chunkSizeRaw, chunkThresholdRaw, maxFileSizeRaw, customLogo string
	s.db.QueryRow("SELECT value FROM settings WHERE key = 'theme'").Scan(&settings.Theme)
	s.db.QueryRow("SELECT value FROM settings WHERE key = 'accent_color'").Scan(&settings.AccentColor)
	s.db.QueryRow("SELECT value FROM settings WHERE key = 'language'").Scan(&settings.Language)
	s.db.QueryRow("SELECT value FROM settings WHERE key = 'chunk_size_bytes'").Scan(&chunkSizeRaw)
	s.db.QueryRow("SELECT value FROM settings WHERE key = 'chunk_threshold'").Scan(&chunkThresholdRaw)
	s.db.QueryRow("SELECT value FROM settings WHERE key = 'max_file_size'").Scan(&maxFileSizeRaw)
	s.db.QueryRow("SELECT value FROM settings WHERE key = 'custom_logo'").Scan(&customLogo)
	if customLogo == "" {
		// Backward compatibility for older key naming used in earlier builds.
		s.db.QueryRow("SELECT value FROM settings WHERE key = 'customlogo'").Scan(&customLogo)
	}
	if v, err := strconv.ParseInt(chunkSizeRaw, 10, 64); err == nil && v > 0 {
		settings.ChunkSizeBytes = v
	}
	if v, err := strconv.ParseInt(chunkThresholdRaw, 10, 64); err == nil && v > 0 {
		settings.ChunkThreshold = v
	}
	if v, err := strconv.ParseInt(maxFileSizeRaw, 10, 64); err == nil && v >= 0 {
		settings.MaxFileSize = v
	}
	settings.CustomLogo = customLogo
	return settings
}

/**
  UpdateSettings upserts each setting key/value pair.
  @param settings - The application settings payload.
  @returns error - An error if the operation fails.
*/
func (s *SQLiteDB) UpdateSettings(settings models.AppSettings) error {
	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('theme', ?)", settings.Theme)
	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('accent_color', ?)", settings.AccentColor)
	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('language', ?)", settings.Language)
	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('chunk_size_bytes', ?)", fmt.Sprintf("%d", settings.ChunkSizeBytes))
	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('chunk_threshold', ?)", fmt.Sprintf("%d", settings.ChunkThreshold))
	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('max_file_size', ?)", fmt.Sprintf("%d", settings.MaxFileSize))
	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('custom_logo', ?)", settings.CustomLogo)
	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('customlogo', ?)", settings.CustomLogo)
	return nil
}

/**
  GetChunkUploads returns all chunk uploads.
  @param none - This function does not accept parameters.
  @returns []models.ChunkUpload - The resulting collection.
*/
func (s *SQLiteDB) GetChunkUploads() []models.ChunkUpload {
	rows, err := s.db.Query("SELECT id, file_name, total_size, total_chunks, received, is_private, custom_link, temp_dir, created_at FROM chunk_uploads")
	if err != nil {
		return []models.ChunkUpload{}
	}
	defer rows.Close()

	var uploads []models.ChunkUpload
	for rows.Next() {
		var u models.ChunkUpload
		var receivedJSON string
		var isPrivate int
		rows.Scan(&u.ID, &u.FileName, &u.TotalSize, &u.TotalChunks, &receivedJSON, &isPrivate, &u.CustomLink, &u.TempDir, &u.CreatedAt)
		json.Unmarshal([]byte(receivedJSON), &u.Received)
		u.IsPrivate = isPrivate == 1
		uploads = append(uploads, u)
	}
	return uploads
}

/**
  GetChunkUpload returns a chunk upload by ID.
  @param id - The identifier to process.
  @returns *models.ChunkUpload - The matching value, or nil when not found.
*/
func (s *SQLiteDB) GetChunkUpload(id string) *models.ChunkUpload {
	var u models.ChunkUpload
	var receivedJSON string
	var isPrivate int
	err := s.db.QueryRow("SELECT id, file_name, total_size, total_chunks, received, is_private, custom_link, temp_dir, created_at FROM chunk_uploads WHERE id = ?", id).
		Scan(&u.ID, &u.FileName, &u.TotalSize, &u.TotalChunks, &receivedJSON, &isPrivate, &u.CustomLink, &u.TempDir, &u.CreatedAt)
	if err != nil {
		return nil
	}
	json.Unmarshal([]byte(receivedJSON), &u.Received)
	u.IsPrivate = isPrivate == 1
	return &u
}

/**
  AddChunkUpload adds a new chunk upload.
  @param upload - The chunk upload payload.
  @returns error - An error if the operation fails.
*/
func (s *SQLiteDB) AddChunkUpload(upload models.ChunkUpload) error {
	// Persist the received bitmap as JSON for compact storage.
	receivedJSON, _ := json.Marshal(upload.Received)
	isPrivate := 0
	if upload.IsPrivate {
		isPrivate = 1
	}
	_, err := s.db.Exec("INSERT INTO chunk_uploads (id, file_name, total_size, total_chunks, received, is_private, custom_link, temp_dir, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		upload.ID, upload.FileName, upload.TotalSize, upload.TotalChunks, string(receivedJSON), isPrivate, upload.CustomLink, upload.TempDir, upload.CreatedAt)
	return err
}

/**
  UpdateChunkReceived marks a chunk as received.
  @param id - The identifier to process.
  @param chunkIndex - The zero-based chunk index.
  @returns error - An error if the operation fails.
*/
func (s *SQLiteDB) UpdateChunkReceived(id string, chunkIndex int) error {
	upload := s.GetChunkUpload(id)
	if upload == nil {
		return errors.New("chunk upload not found")
	}
	upload.Received[chunkIndex] = true
	receivedJSON, _ := json.Marshal(upload.Received)
	_, err := s.db.Exec("UPDATE chunk_uploads SET received = ? WHERE id = ?", string(receivedJSON), id)
	return err
}

/**
  RemoveChunkUpload removes a chunk upload by ID.
  @param id - The identifier to process.
  @returns error - An error if the operation fails.
*/
func (s *SQLiteDB) RemoveChunkUpload(id string) error {
	result, err := s.db.Exec("DELETE FROM chunk_uploads WHERE id = ?", id)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("chunk upload not found")
	}
	return nil
}
