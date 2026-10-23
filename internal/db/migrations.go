package db

import (
	"context"
	"database/sql"
	"fmt"
)

// Migrate runs the necessary database migrations based on the DB type (sqlite or postgres).
func Migrate(ctx context.Context, db *sql.DB, dbType string) error {
	var query string
	switch dbType {
	case "sqlite":
		query = `
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			session_version INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS files (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			original_name TEXT NOT NULL,
			custom_name TEXT NOT NULL,
			url_path TEXT UNIQUE NOT NULL,
			size INTEGER NOT NULL,
			is_private BOOLEAN NOT NULL DEFAULT 0,
			storage_type TEXT NOT NULL,
			storage_path TEXT NOT NULL,
			uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			stats_enabled BOOLEAN NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS file_reads (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			file_id INTEGER NOT NULL,
			device_type TEXT NOT NULL,
			read_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_file_reads_file_at ON file_reads(file_id, read_at);
		CREATE INDEX IF NOT EXISTS idx_file_reads_read_at ON file_reads(read_at);`
	case "postgres":
		query = `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(50) NOT NULL DEFAULT 'user',
			session_version INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE IF NOT EXISTS files (
			id SERIAL PRIMARY KEY,
			original_name VARCHAR(255) NOT NULL,
			custom_name VARCHAR(255) NOT NULL,
			url_path VARCHAR(255) UNIQUE NOT NULL,
			size BIGINT NOT NULL,
			is_private BOOLEAN NOT NULL DEFAULT false,
			storage_type VARCHAR(50) NOT NULL,
			storage_path VARCHAR(255) NOT NULL,
			uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			stats_enabled BOOLEAN NOT NULL DEFAULT false
		);
		CREATE TABLE IF NOT EXISTS file_reads (
			id SERIAL PRIMARY KEY,
			file_id INTEGER NOT NULL,
			device_type VARCHAR(32) NOT NULL,
			read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS idx_file_reads_file_at ON file_reads(file_id, read_at);
		CREATE INDEX IF NOT EXISTS idx_file_reads_read_at ON file_reads(read_at);`
	default:
		return fmt.Errorf("unsupported db type for migrations: %s", dbType)
	}

	_, err := db.ExecContext(ctx, query)
	if err != nil {
		return err
	}

	// Try to add new columns (ignore errors if they already exist)
	if dbType == "sqlite" {
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT ''")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN webauthn_data TEXT DEFAULT '[]'")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN storage_quota_mb INTEGER DEFAULT 0")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'global'")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN accent TEXT DEFAULT 'global'")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN language TEXT DEFAULT ''")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN recovery_code_hash TEXT DEFAULT ''")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN embed_config TEXT DEFAULT ''")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN last_totp_step BIGINT DEFAULT 0")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
		db.ExecContext(ctx, "ALTER TABLE files ADD COLUMN user_id INTEGER DEFAULT 1")
		db.ExecContext(ctx, "ALTER TABLE files ADD COLUMN stats_enabled BOOLEAN DEFAULT 0")
		db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS file_reads (id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL, device_type TEXT NOT NULL, read_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_files_user_uploaded ON files(user_id, uploaded_at DESC, id DESC)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_files_uploaded ON files(uploaded_at DESC, id DESC)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_file_reads_file_at ON file_reads(file_id, read_at)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_file_reads_read_at ON file_reads(read_at)")
		db.ExecContext(ctx, "DROP INDEX IF EXISTS idx_file_reads_file_id")
	} else if dbType == "postgres" {
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN totp_secret VARCHAR(255) DEFAULT ''")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN webauthn_data TEXT DEFAULT '[]'")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN storage_quota_mb INTEGER DEFAULT 0")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN theme VARCHAR(50) DEFAULT 'global'")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN accent VARCHAR(50) DEFAULT 'global'")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN language VARCHAR(50) DEFAULT ''")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN recovery_code_hash VARCHAR(255) DEFAULT ''")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN embed_config TEXT DEFAULT ''")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN last_totp_step BIGINT DEFAULT 0")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
		db.ExecContext(ctx, "ALTER TABLE files ADD COLUMN user_id INTEGER DEFAULT 1")
		db.ExecContext(ctx, "ALTER TABLE files ADD COLUMN stats_enabled BOOLEAN DEFAULT false")
		db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS file_reads (id SERIAL PRIMARY KEY, file_id INTEGER NOT NULL, device_type VARCHAR(32) NOT NULL, read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_files_user_uploaded ON files(user_id, uploaded_at DESC, id DESC)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_files_uploaded ON files(uploaded_at DESC, id DESC)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_file_reads_file_at ON file_reads(file_id, read_at)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_file_reads_read_at ON file_reads(read_at)")
		db.ExecContext(ctx, "DROP INDEX IF EXISTS idx_file_reads_file_id")
	}

	return nil
}
