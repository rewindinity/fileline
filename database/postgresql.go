package database

import (
	"context"
	"encoding/json"
	"fileline/models"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQLDB implements DatabaseInterface on top of PostgreSQL.
type PostgreSQLDB struct {
	pool *pgxpool.Pool
}

/**
  Load validates config, opens a connection pool, and ensures required tables exist.
  @param none - This function does not accept parameters.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) Load() error {
	if p.pool != nil {
		Debugf("Disconnecting previous PostgreSQL pool before reconnect")
		p.pool.Close()
		p.pool = nil
	}
	// Parse connection details from config
	// PgHost format: "host:port"
	// PgUser format: "user:password"
	hostPort := strings.Split(Config.PgHost, ":")
	if len(hostPort) != 2 {
		Debugf("PostgreSQL Load failed: invalid pg_host format: %q", Config.PgHost)
		return fmt.Errorf("invalid pg_host format, expected host:port")
	}
	userPass := strings.Split(Config.PgUser, ":")
	if len(userPass) != 2 {
		Debugf("PostgreSQL Load failed: invalid pg_user format")
		return fmt.Errorf("invalid pg_user format, expected user:password")
	}
	Debugf("Connecting to PostgreSQL host=%s port=%s database=%q user=%q", hostPort[0], hostPort[1], Config.PgDatabase, userPass[0])
	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s", userPass[0], userPass[1], hostPort[0], hostPort[1], Config.PgDatabase)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		Debugf("PostgreSQL connect failed: %v", err)
		return fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		Debugf("PostgreSQL ping failed: %v", err)
		Debugf("Disconnecting PostgreSQL pool after failed ping")
		pool.Close()
		return fmt.Errorf("failed to ping PostgreSQL: %v", err)
	}
	p.pool = pool
	Debugf("PostgreSQL connection established")
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		created_at TEXT NOT NULL,
		two_fa_enabled BOOLEAN DEFAULT FALSE,
		two_fa_secret TEXT,
		backup_code TEXT,
		passkeys JSONB
	);

	CREATE TABLE IF NOT EXISTS files (
		id TEXT PRIMARY KEY,
		filename TEXT NOT NULL,
		link TEXT UNIQUE NOT NULL,
		upload_date TEXT NOT NULL,
		size_bytes BIGINT NOT NULL,
		is_private BOOLEAN DEFAULT FALSE
	);

	CREATE TABLE IF NOT EXISTS settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS chunk_uploads (
		upload_id TEXT PRIMARY KEY,
		filename TEXT NOT NULL,
		total_chunks INTEGER NOT NULL,
		total_size BIGINT NOT NULL,
		received TEXT NOT NULL,
		is_private BOOLEAN DEFAULT FALSE,
		custom_link TEXT,
		temp_dir TEXT NOT NULL DEFAULT '',
		created_at TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);`
	_, err = p.pool.Exec(ctx, schema)
	if err != nil {
		Debugf("PostgreSQL schema initialization failed: %v", err)
		return err
	}
	_, err = p.pool.Exec(ctx, "ALTER TABLE chunk_uploads ADD COLUMN IF NOT EXISTS temp_dir TEXT NOT NULL DEFAULT ''")
	if err != nil {
		Debugf("PostgreSQL schema migration failed: %v", err)
		return err
	}
	Debugf("PostgreSQL schema ready")
	return err
}

/**
  Save is a no-op because PostgreSQL writes are durable per statement.
  @param none - This function does not accept parameters.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) Save() error {
	// PostgreSQL auto-saves, nothing to do
	return nil
}

/**
  GetUser returns the single user record used by the application.
  @param none - This function does not accept parameters.
  @returns *models.User - The matching value, or nil when not found.
*/
func (p *PostgreSQLDB) GetUser() *models.User {
	if p.pool == nil {
		return nil
	}
	ctx := context.Background()
	var user models.User
	var passkeysJSON string
	err := p.pool.QueryRow(ctx,
		"SELECT username, password_hash, created_at, two_fa_enabled, COALESCE(two_fa_secret, ''), COALESCE(backup_code, ''), COALESCE(passkeys::text, '[]') FROM users LIMIT 1",
	).Scan(&user.Username, &user.PasswordHash, &user.CreatedAt, &user.TwoFAEnabled, &user.TwoFASecret, &user.BackupCode, &passkeysJSON)
	if err != nil {
		return nil
	}
	// Deserialize passkeys
	if passkeysJSON != "" && passkeysJSON != "[]" {
		json.Unmarshal([]byte(passkeysJSON), &user.Passkeys)
	}
	return &user
}

/**
  SetUser replaces the single user row.
  @param user - The user record to persist.
  @returns void
*/
func (p *PostgreSQLDB) SetUser(user *models.User) {
	if p.pool == nil {
		return
	}
	ctx := context.Background()
	// Serialize passkeys
	passkeysJSON, _ := json.Marshal(user.Passkeys)
	// FileLine uses a single account row; replace for deterministic reads.
	p.pool.Exec(ctx, "DELETE FROM users")
	p.pool.Exec(ctx,
		"INSERT INTO users (username, password_hash, created_at, two_fa_enabled, two_fa_secret, backup_code, passkeys) VALUES ($1, $2, $3, $4, $5, $6, $7)",
		user.Username, user.PasswordHash, user.CreatedAt, user.TwoFAEnabled, user.TwoFASecret, user.BackupCode, string(passkeysJSON),
	)
}

/**
  GetFiles returns file metadata ordered by upload timestamp (newest first).
  @param none - This function does not accept parameters.
  @returns []models.FileEntry - The resulting collection.
*/
func (p *PostgreSQLDB) GetFiles() []models.FileEntry {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx,
		"SELECT id, filename, link, upload_date, size_bytes, is_private FROM files ORDER BY upload_date DESC",
	)
	if err != nil {
		return []models.FileEntry{}
	}
	defer rows.Close()
	var files []models.FileEntry
	for rows.Next() {
		var file models.FileEntry
		if err := rows.Scan(&file.ID, &file.Name, &file.Link, &file.UploadedAt, &file.Size, &file.IsPrivate); err == nil {
			files = append(files, file)
		}
	}
	return files
}

/**
  AddFile inserts a new file metadata row.
  @param file - The file entry to store.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) AddFile(file models.FileEntry) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx,
		"INSERT INTO files (id, filename, link, upload_date, size_bytes, is_private) VALUES ($1, $2, $3, $4, $5, $6)",
		file.ID, file.Name, file.Link, file.UploadedAt, file.Size, file.IsPrivate,
	)
	return err
}

/**
  UpdateFile updates mutable file metadata for a given ID.
  @param id - The identifier to process.
  @param name - The file name.
  @param link - The public link value.
  @param isPrivate - Whether the file should be private.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) UpdateFile(id string, name, link string, isPrivate bool) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx,
		"UPDATE files SET filename = $1, link = $2, is_private = $3 WHERE id = $4",
		name, link, isPrivate, id,
	)
	return err
}

/**
  DeleteFile removes a file metadata row.
  @param fileID - The file identifier.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) DeleteFile(fileID string) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx, "DELETE FROM files WHERE id = $1", fileID)
	return err
}

/**
  GetFileByID returns one file by internal ID.
  @param fileID - The file identifier.
  @returns *models.FileEntry - The matching value, or nil when not found.
*/
func (p *PostgreSQLDB) GetFileByID(fileID string) *models.FileEntry {
	ctx := context.Background()
	var file models.FileEntry
	err := p.pool.QueryRow(ctx,
		"SELECT id, filename, link, upload_date, size_bytes, is_private FROM files WHERE id = $1",
		fileID,
	).Scan(&file.ID, &file.Name, &file.Link, &file.UploadedAt, &file.Size, &file.IsPrivate)
	if err != nil {
		return nil
	}
	return &file
}

/**
  GetFileByLink returns one file by public link.
  @param link - The public link value.
  @returns *models.FileEntry - The matching value, or nil when not found.
*/
func (p *PostgreSQLDB) GetFileByLink(link string) *models.FileEntry {
	ctx := context.Background()
	var file models.FileEntry
	err := p.pool.QueryRow(ctx,
		"SELECT id, filename, link, upload_date, size_bytes, is_private FROM files WHERE link = $1",
		link,
	).Scan(&file.ID, &file.Name, &file.Link, &file.UploadedAt, &file.Size, &file.IsPrivate)
	if err != nil {
		return nil
	}
	return &file
}

/**
  GetSettings hydrates app settings from key/value rows with sane defaults.
  @param none - This function does not accept parameters.
  @returns models.AppSettings - The resulting value.
*/
func (p *PostgreSQLDB) GetSettings() models.AppSettings {
	settings := models.AppSettings{
		Theme:          "dark-blue",
		AccentColor:    "#3b82f6",
		Language:       "en",
		ChunkSizeBytes: 5 * 1024 * 1024,
		ChunkThreshold: 100 * 1024 * 1024,
		MaxFileSize:    0,
	}
	if p.pool == nil {
		return settings
	}
	ctx := context.Background()
	rows, err := p.pool.Query(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return settings
	}
	defer rows.Close()
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			continue
		}
		switch key {
		case "theme":
			settings.Theme = value
		case "accent_color":
			settings.AccentColor = value
		case "language":
			settings.Language = value
		case "chunk_size_bytes":
			fmt.Sscanf(value, "%d", &settings.ChunkSizeBytes)
		case "chunk_threshold":
			fmt.Sscanf(value, "%d", &settings.ChunkThreshold)
		case "max_file_size":
			fmt.Sscanf(value, "%d", &settings.MaxFileSize)
		case "custom_logo", "customlogo":
			settings.CustomLogo = value
		}
	}
	return settings
}

/**
  UpdateSettings upserts all settings keys in a single batch.
  @param settings - The application settings payload.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) UpdateSettings(settings models.AppSettings) error {
	ctx := context.Background()
	batch := &pgx.Batch{}
	batch.Queue("INSERT INTO settings (key, value) VALUES ('theme', $1) ON CONFLICT (key) DO UPDATE SET value = $1", settings.Theme)
	batch.Queue("INSERT INTO settings (key, value) VALUES ('accent_color', $1) ON CONFLICT (key) DO UPDATE SET value = $1", settings.AccentColor)
	batch.Queue("INSERT INTO settings (key, value) VALUES ('language', $1) ON CONFLICT (key) DO UPDATE SET value = $1", settings.Language)
	batch.Queue("INSERT INTO settings (key, value) VALUES ('chunk_size_bytes', $1) ON CONFLICT (key) DO UPDATE SET value = $1", fmt.Sprintf("%d", settings.ChunkSizeBytes))
	batch.Queue("INSERT INTO settings (key, value) VALUES ('chunk_threshold', $1) ON CONFLICT (key) DO UPDATE SET value = $1", fmt.Sprintf("%d", settings.ChunkThreshold))
	batch.Queue("INSERT INTO settings (key, value) VALUES ('max_file_size', $1) ON CONFLICT (key) DO UPDATE SET value = $1", fmt.Sprintf("%d", settings.MaxFileSize))
	batch.Queue("INSERT INTO settings (key, value) VALUES ('custom_logo', $1) ON CONFLICT (key) DO UPDATE SET value = $1", settings.CustomLogo)
	batch.Queue("INSERT INTO settings (key, value) VALUES ('customlogo', $1) ON CONFLICT (key) DO UPDATE SET value = $1", settings.CustomLogo)
	br := p.pool.SendBatch(ctx, batch)
	defer br.Close()
	for i := 0; i < 8; i++ {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

/**
  GetChunkUploads returns all tracked chunked uploads.
  @param none - This function does not accept parameters.
  @returns []models.ChunkUpload - The resulting collection.
*/
func (p *PostgreSQLDB) GetChunkUploads() []models.ChunkUpload {
	ctx := context.Background()
	rows, err := p.pool.Query(ctx,
		"SELECT upload_id, filename, total_chunks, total_size, received, is_private, COALESCE(custom_link, ''), temp_dir, created_at FROM chunk_uploads",
	)
	if err != nil {
		return []models.ChunkUpload{}
	}
	defer rows.Close()
	var chunks []models.ChunkUpload
	for rows.Next() {
		var chunk models.ChunkUpload
		var receivedJSON string
		if err := rows.Scan(&chunk.ID, &chunk.FileName, &chunk.TotalChunks, &chunk.TotalSize,
			&receivedJSON, &chunk.IsPrivate, &chunk.CustomLink, &chunk.TempDir, &chunk.CreatedAt); err != nil {
			continue
		}
		json.Unmarshal([]byte(receivedJSON), &chunk.Received)
		chunks = append(chunks, chunk)
	}
	return chunks
}

/**
  AddChunkUpload stores tracking metadata for a chunked upload.
  @param chunk - The chunk upload payload.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) AddChunkUpload(chunk models.ChunkUpload) error {
	ctx := context.Background()
	receivedJSON, _ := json.Marshal(chunk.Received)
	_, err := p.pool.Exec(ctx,
		"INSERT INTO chunk_uploads (upload_id, filename, total_chunks, total_size, received, is_private, custom_link, temp_dir, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		chunk.ID, chunk.FileName, chunk.TotalChunks, chunk.TotalSize, string(receivedJSON), chunk.IsPrivate, chunk.CustomLink, chunk.TempDir, chunk.CreatedAt,
	)
	return err
}

/**
  UpdateChunkUpload replaces persisted chunk upload metadata.
  @param chunk - The chunk upload payload.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) UpdateChunkUpload(chunk models.ChunkUpload) error {
	ctx := context.Background()
	receivedJSON, _ := json.Marshal(chunk.Received)
	_, err := p.pool.Exec(ctx,
		"UPDATE chunk_uploads SET filename = $1, total_chunks = $2, total_size = $3, received = $4, is_private = $5, custom_link = $6, temp_dir = $7, created_at = $8 WHERE upload_id = $9",
		chunk.FileName, chunk.TotalChunks, chunk.TotalSize, string(receivedJSON), chunk.IsPrivate, chunk.CustomLink, chunk.TempDir, chunk.CreatedAt, chunk.ID,
	)
	return err
}

/**
  RemoveChunkUpload deletes chunk-upload tracking metadata.
  @param uploadID - The chunk upload identifier.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) RemoveChunkUpload(uploadID string) error {
	ctx := context.Background()
	_, err := p.pool.Exec(ctx, "DELETE FROM chunk_uploads WHERE upload_id = $1", uploadID)
	return err
}

/**
  GetChunkUpload returns tracked upload metadata for a specific upload ID.
  @param uploadID - The chunk upload identifier.
  @returns *models.ChunkUpload - The matching value, or nil when not found.
*/
func (p *PostgreSQLDB) GetChunkUpload(uploadID string) *models.ChunkUpload {
	ctx := context.Background()
	var chunk models.ChunkUpload
	var receivedJSON string
	err := p.pool.QueryRow(ctx,
		"SELECT upload_id, filename, total_chunks, total_size, received, is_private, COALESCE(custom_link, ''), temp_dir, created_at FROM chunk_uploads WHERE upload_id = $1",
		uploadID,
	).Scan(&chunk.ID, &chunk.FileName, &chunk.TotalChunks, &chunk.TotalSize,
		&receivedJSON, &chunk.IsPrivate, &chunk.CustomLink, &chunk.TempDir, &chunk.CreatedAt)
	if err != nil {
		return nil
	}
	json.Unmarshal([]byte(receivedJSON), &chunk.Received)
	return &chunk
}

/**
  IsConfigured reads setup state and propagates unexpected DB errors for diagnostics.
  @param none - This function does not accept parameters.
  @returns bool - True when is configured is satisfied; otherwise false.
*/
func (p *PostgreSQLDB) IsConfigured() bool {
	if p.pool == nil {
		return false
	}
	ctx := context.Background()
	var value string
	err := p.pool.QueryRow(ctx,
		"SELECT value FROM config WHERE key = 'configured'",
	).Scan(&value)
	if err != nil {
		if err != pgx.ErrNoRows {
			ConnectionError = err
		} else {
			ConnectionError = nil
		}
		return false
	}
	ConnectionError = nil
	return value == "true"
}

/**
  SetConfigured upserts the setup-completion flag.
  @param configured - Whether initial setup is complete.
  @returns void
*/
func (p *PostgreSQLDB) SetConfigured(configured bool) {
	ctx := context.Background()
	value := "false"
	if configured {
		value = "true"
	}
	p.pool.Exec(ctx,
		"INSERT INTO config (key, value) VALUES ('configured', $1) ON CONFLICT (key) DO UPDATE SET value = $1",
		value,
	)
}

/**
  LinkExists checks whether a public link token is already used.
  @param link - The public link value.
  @returns bool - True when link exists is satisfied; otherwise false.
*/
func (p *PostgreSQLDB) LinkExists(link string) bool {
	files := p.GetFiles()
	for _, f := range files {
		if f.Link == link {
			return true
		}
	}
	return false
}

/**
  InitDefaults initializes the database with defaults.
  @param none - This function does not accept parameters.
  @returns void
*/
func (p *PostgreSQLDB) InitDefaults() {
	// PostgreSQL tables created in Load(), nothing to do
}

/**
  UpdateChunkReceived marks a chunk as received.
  @param id - The identifier to process.
  @param chunkIndex - The zero-based chunk index.
  @returns error - An error if the operation fails.
*/
func (p *PostgreSQLDB) UpdateChunkReceived(id string, chunkIndex int) error {
	chunk := p.GetChunkUpload(id)
	if chunk == nil {
		return fmt.Errorf("chunk upload not found")
	}
	if chunkIndex >= 0 && chunkIndex < len(chunk.Received) {
		chunk.Received[chunkIndex] = true
		// Update in database
		ctx := context.Background()
		receivedJSON, _ := json.Marshal(chunk.Received)
		_, err := p.pool.Exec(ctx,
			"UPDATE chunk_uploads SET received = $1 WHERE upload_id = $2",
			string(receivedJSON), id,
		)
		return err
	}
	return fmt.Errorf("invalid chunk index")
}
