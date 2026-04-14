package database

import (
	"encoding/json"
	"os"
	"strings"
	"sync"

	"fileline/models"
)

// DatabaseInterface defines backend-agnostic persistence operations used by handlers.
type DatabaseInterface interface {
	// Core operations
	Load() error
	Save() error
	InitDefaults()
	IsConfigured() bool
	SetConfigured(bool)
	// User operations
	GetUser() *models.User
	SetUser(user *models.User)
	// File operations
	GetFiles() []models.FileEntry
	GetFileByID(id string) *models.FileEntry
	GetFileByLink(link string) *models.FileEntry
	LinkExists(link string) bool
	AddFile(file models.FileEntry) error
	UpdateFile(id string, name, link string, isPrivate bool) error
	DeleteFile(id string) error
	// Settings operations
	GetSettings() models.AppSettings
	UpdateSettings(settings models.AppSettings) error
	// Chunk upload operations
	GetChunkUploads() []models.ChunkUpload
	GetChunkUpload(id string) *models.ChunkUpload
	AddChunkUpload(upload models.ChunkUpload) error
	UpdateChunkReceived(id string, chunkIndex int) error
	RemoveChunkUpload(id string) error
}

var (
	// DB points to the active backend implementation selected from config.
	DB DatabaseInterface
	// DBMutex coordinates concurrent access across request handlers.
	DBMutex sync.RWMutex
	// Config is the persisted runtime configuration loaded from config.json.
	Config models.Config
	// ConnectionError stores the latest backend connectivity error for UI reporting.
	ConnectionError error
)

/*
*

	InitDatabase selects the configured backend and establishes initial connectivity.
	@param none - This function does not accept parameters.
	@returns error - An error if the operation fails.
*/
func InitDatabase() error {
	ConnectionError = nil // Reset error
	originalType := Config.DatabaseType
	switch strings.ToLower(strings.TrimSpace(Config.DatabaseType)) {
	case "", "sqlite", "json":
		// JSON backend has been removed; default to SQLite.
		Config.DatabaseType = "sqlite"
		DB = &SQLiteDB{}
	case "mongodb":
		Config.DatabaseType = "mongodb"
		DB = &MongoDB{}
	case "postgresql":
		Config.DatabaseType = "postgresql"
		DB = &PostgreSQLDB{}
	default:
		Config.DatabaseType = "sqlite"
		DB = &SQLiteDB{}
	}
	if Config.DatabaseType != originalType {
		_ = SaveConfig()
	}
	err := DB.Load()
	if err != nil {
		// For SQLite, initialize defaults when database file does not exist yet.
		if os.IsNotExist(err) && Config.DatabaseType == "sqlite" {
			DB.InitDefaults()
			return nil // No error, just initialized with defaults
		}
		// Preserve backend error for UI diagnostics and disable DB usage until recovered.
		ConnectionError = err
		DB = nil
	}
	return err
}

/*
*

	LoadConfig loads the configuration from file.
	@param none - This function does not accept parameters.
	@returns error - An error if the operation fails.
*/
func LoadConfig() error {
	data, err := os.ReadFile(models.ConfigFile)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &Config)
}

/*
*

	SaveConfig saves the configuration to file.
	@param none - This function does not accept parameters.
	@returns error - An error if the operation fails.
*/
func SaveConfig() error {
	data, err := json.MarshalIndent(Config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(models.ConfigFile, data, 0644)
}

/*
*

	InitConfigDefaults initializes config with default values.
	@param none - This function does not accept parameters.
	@returns void
*/
func InitConfigDefaults() {
	Config = models.Config{
		Port:         8080,
		DatabaseType: "sqlite",
	}
	SaveConfig()
}

/*
*

	LoadDatabase reloads backend data from the selected persistence layer.
	@param none - This function does not accept parameters.
	@returns error - An error if the operation fails.
*/
func LoadDatabase() error {
	return DB.Load()
}

/*
*

	SaveDatabase flushes in-memory changes when the backend requires explicit persistence.
	@param none - This function does not accept parameters.
	@returns error - An error if the operation fails.
*/
func SaveDatabase() error {
	return DB.Save()
}

/*
*

	GetFileByID returns a file by internal ID, or nil when not found.
	@param id - The identifier to process.
	@returns *models.FileEntry - The matching value, or nil when not found.
*/
func GetFileByID(id string) *models.FileEntry {
	if DB == nil {
		return nil
	}
	DBMutex.RLock()
	defer DBMutex.RUnlock()
	return DB.GetFileByID(id)
}

/*
*

	GetFileByLink returns a file by public link, or nil when not found.
	@param link - The public link value.
	@returns *models.FileEntry - The matching value, or nil when not found.
*/
func GetFileByLink(link string) *models.FileEntry {
	if DB == nil {
		return nil
	}
	DBMutex.RLock()
	defer DBMutex.RUnlock()
	return DB.GetFileByLink(link)
}

/*
*

	LinkExists reports whether a public link is already in use.
	@param link - The public link value.
	@returns bool - True when link exists is satisfied; otherwise false.
*/
func LinkExists(link string) bool {
	if DB == nil {
		return false
	}
	DBMutex.RLock()
	defer DBMutex.RUnlock()
	return DB.LinkExists(link)
}

/*
*

	AddFile stores a new file entry and persists the update.
	@param file - The file entry to store.
	@returns void
*/
func AddFile(file models.FileEntry) {
	// Persist outside the critical section to reduce lock hold time.
	DBMutex.Lock()
	DB.AddFile(file)
	DBMutex.Unlock()
	DB.Save()
}

/*
*

	UpdateFile updates mutable file metadata and persists on success.
	@param id - The identifier to process.
	@param name - The file name.
	@param link - The public link value.
	@param isPrivate - Whether the file should be private.
	@returns bool - True when update file is satisfied; otherwise false.
*/
func UpdateFile(id string, name, link string, isPrivate bool) bool {
	// Apply mutation under lock, then flush once mutation is confirmed.
	DBMutex.Lock()
	err := DB.UpdateFile(id, name, link, isPrivate)
	DBMutex.Unlock()
	if err == nil {
		DB.Save()
		return true
	}
	return false
}

/*
*

	DeleteFile removes a file entry and persists on success.
	@param id - The identifier to process.
	@returns bool - True when delete file is satisfied; otherwise false.
*/
func DeleteFile(id string) bool {
	// Apply mutation under lock, then flush once mutation is confirmed.
	DBMutex.Lock()
	err := DB.DeleteFile(id)
	DBMutex.Unlock()
	if err == nil {
		DB.Save()
		return true
	}
	return false
}

/*
*

	GetChunkUploads returns all tracked chunk-upload states.
	@param none - This function does not accept parameters.
	@returns []models.ChunkUpload - The resulting collection.
*/
func GetChunkUploads() []models.ChunkUpload {
	DBMutex.RLock()
	defer DBMutex.RUnlock()
	return DB.GetChunkUploads()
}

/*
*

	GetChunkUpload returns tracked upload state for a given upload ID.
	@param id - The identifier to process.
	@returns *models.ChunkUpload - The matching value, or nil when not found.
*/
func GetChunkUpload(id string) *models.ChunkUpload {
	DBMutex.RLock()
	defer DBMutex.RUnlock()
	return DB.GetChunkUpload(id)
}

/*
*

	AddChunkUpload creates tracking state for a new chunked upload.
	@param upload - The chunk upload payload.
	@returns void
*/
func AddChunkUpload(upload models.ChunkUpload) {
	DBMutex.Lock()
	DB.AddChunkUpload(upload)
	DBMutex.Unlock()
	DB.Save()
}

/*
*

	UpdateChunkReceived marks a chunk index as received for an in-progress upload.
	@param id - The identifier to process.
	@param chunkIndex - The zero-based chunk index.
	@returns void
*/
func UpdateChunkReceived(id string, chunkIndex int) {
	DBMutex.Lock()
	DB.UpdateChunkReceived(id, chunkIndex)
	DBMutex.Unlock()
	DB.Save()
}

/*
*

	RemoveChunkUpload deletes upload-tracking state after completion or cancellation.
	@param id - The identifier to process.
	@returns void
*/
func RemoveChunkUpload(id string) {
	DBMutex.Lock()
	DB.RemoveChunkUpload(id)
	DBMutex.Unlock()
	DB.Save()
}

/*
*

	InitDefaults initializes backend defaults and persists them when applicable.
	@param none - This function does not accept parameters.
	@returns void
*/
func InitDefaults() {
	DB.InitDefaults()
	DB.Save()
}

/*
*

	GetUser returns the single configured user account.
	@param none - This function does not accept parameters.
	@returns *models.User - The matching value, or nil when not found.
*/
func GetUser() *models.User {
	if DB == nil {
		return nil
	}
	DBMutex.RLock()
	defer DBMutex.RUnlock()
	return DB.GetUser()
}

/*
*

	SetUser replaces the stored user record.
	@param user - The user record to persist.
	@returns void
*/
func SetUser(user *models.User) {
	if DB == nil {
		return
	}
	DBMutex.Lock()
	defer DBMutex.Unlock()
	DB.SetUser(user)
	DB.Save()
}

/*
*

	GetSettings returns app settings, including safe defaults when DB is unavailable.
	@param none - This function does not accept parameters.
	@returns models.AppSettings - The resulting value.
*/
func GetSettings() models.AppSettings {
	if DB == nil {
		// Return defaults when DB not initialized
		return models.AppSettings{
			Theme:          "dark-blue",
			AccentColor:    "#3b82f6",
			Language:       "en",
			ChunkSizeBytes: 5 * 1024 * 1024,
			ChunkThreshold: 100 * 1024 * 1024,
			MaxFileSize:    0,
			CustomLogo:     "",
		}
	}
	DBMutex.RLock()
	defer DBMutex.RUnlock()
	settings := DB.GetSettings()
	settings.CustomLogo = normalizeCustomLogo(settings.CustomLogo)
	return settings
}

/*
*

	UpdateSettings persists application settings.
	@param settings - The application settings payload.
	@returns void
*/
func UpdateSettings(settings models.AppSettings) {
	if DB == nil {
		return
	}
	DBMutex.Lock()
	defer DBMutex.Unlock()
	DB.UpdateSettings(settings)
	DB.Save()
}

/*
*

	GetFiles returns all known file entries.
	@param none - This function does not accept parameters.
	@returns []models.FileEntry - The resulting collection.
*/
func GetFiles() []models.FileEntry {
	if DB == nil {
		return []models.FileEntry{}
	}
	DBMutex.RLock()
	defer DBMutex.RUnlock()
	return DB.GetFiles()
}

/*
*

	IsConfigured reports whether setup has been completed for the active backend.
	@param none - This function does not accept parameters.
	@returns bool - True when is configured is satisfied; otherwise false.
*/
func IsConfigured() bool {
	// If DB is nil (database not initialized yet), return false
	if DB == nil {
		return false
	}
	DBMutex.RLock()
	defer DBMutex.RUnlock()
	return DB.IsConfigured()
}

/*
*

	SetConfigured marks setup completion state and persists the flag.
	@param configured - Whether initial setup is complete.
	@returns void
*/
func SetConfigured(configured bool) {
	// Only set configured if DB is initialized
	if DB == nil {
		return
	}
	DBMutex.Lock()
	defer DBMutex.Unlock()
	DB.SetConfigured(configured)
	DB.Save()
}

/*
*

	HasConnectionError returns true if there was a database connection error.
	@param none - This function does not accept parameters.
	@returns bool - True when has connection error is satisfied; otherwise false.
*/
func HasConnectionError() bool {
	return ConnectionError != nil
}

/*
*

	GetConnectionError returns the database connection error message.
	@param none - This function does not accept parameters.
	@returns string - The resulting string value.
*/
func GetConnectionError() string {
	if ConnectionError != nil {
		return ConnectionError.Error()
	}
	return ""
}
