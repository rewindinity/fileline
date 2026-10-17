package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// Migrate runs the necessary database migrations based on the DB type
func Migrate(ctx context.Context, db *sql.DB, dbType string) error {
	var query string
	switch dbType {
	case "sqlite":
		query = `
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user'
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
		CREATE INDEX IF NOT EXISTS idx_file_reads_file_id ON file_reads(file_id);
		CREATE INDEX IF NOT EXISTS idx_file_reads_read_at ON file_reads(read_at);`
	case "postgres":
		query = `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(50) NOT NULL DEFAULT 'user'
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
		CREATE INDEX IF NOT EXISTS idx_file_reads_file_id ON file_reads(file_id);
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
		db.ExecContext(ctx, "ALTER TABLE files ADD COLUMN user_id INTEGER DEFAULT 1")
		db.ExecContext(ctx, "ALTER TABLE files ADD COLUMN stats_enabled BOOLEAN DEFAULT 0")
		db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS file_reads (id INTEGER PRIMARY KEY AUTOINCREMENT, file_id INTEGER NOT NULL, device_type TEXT NOT NULL, read_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_file_reads_file_id ON file_reads(file_id)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_file_reads_read_at ON file_reads(read_at)")
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
		db.ExecContext(ctx, "ALTER TABLE files ADD COLUMN user_id INTEGER DEFAULT 1")
		db.ExecContext(ctx, "ALTER TABLE files ADD COLUMN stats_enabled BOOLEAN DEFAULT false")
		db.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS file_reads (id SERIAL PRIMARY KEY, file_id INTEGER NOT NULL, device_type VARCHAR(32) NOT NULL, read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_file_reads_file_id ON file_reads(file_id)")
		db.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS idx_file_reads_read_at ON file_reads(read_at)")
	}

	return nil
}

// HasAdmin checks if there is at least one admin user in the database.
func HasAdmin(ctx context.Context, db *sql.DB) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// ErrAdminAlreadyExists is returned when CreateAdmin is called after an admin already exists
var ErrAdminAlreadyExists = fmt.Errorf("admin user already exists")

// CreateAdmin atomically creates the initial admin user only if no admin currently exists
func CreateAdmin(ctx context.Context, db *sql.DB, username, passwordHash string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, role) SELECT $1, $2, 'admin' WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'admin')",
		username, passwordHash)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrAdminAlreadyExists
	}
	return tx.Commit()
}

// EmbedConfig holds personal media preview / Discord embed preferences for a user.
type EmbedConfig struct {
	Enabled        bool   `json:"enabled"`
	Color          string `json:"color"`
	UseAccentColor bool   `json:"use_accent_color"`
	SiteName       string `json:"site_name"`
	CustomText     string `json:"custom_text"`
	ShowTitle      bool   `json:"show_title"`
	ShowSize       bool   `json:"show_size"`
	ShowDate       bool   `json:"show_date"`
	ShowAuthor     bool   `json:"show_author"`
}

// DefaultEmbedConfig returns the default personal embed configuration (plain URL by default).
func DefaultEmbedConfig() EmbedConfig {
	return EmbedConfig{
		Enabled:        false,
		Color:          "#1d9bf0",
		UseAccentColor: false,
		SiteName:       "FileLine",
		CustomText:     "",
		ShowTitle:      true,
		ShowSize:       true,
		ShowDate:       true,
		ShowAuthor:     true,
	}
}

// ParseEmbedConfig parses JSON-serialized embed config or returns defaults.
func ParseEmbedConfig(raw string) EmbedConfig {
	cfg := DefaultEmbedConfig()
	if raw == "" {
		return cfg
	}
	_ = json.Unmarshal([]byte(raw), &cfg)
	if cfg.Color == "" {
		cfg.Color = "#1d9bf0"
	}
	return cfg
}

type User struct {
	ID               int
	Username         string
	PasswordHash     string
	Role             string
	TOTPSecret       string
	LastTOTPStep     int64
	WebAuthnData     string
	StorageQuotaMB   int
	Theme            string
	Accent           string
	Language         string
	RecoveryCodeHash string
	EmbedConfigJSON  string
	EmbedConfig      EmbedConfig
}

// GetUserByUsername retrieves a user by username.
func GetUserByUsername(ctx context.Context, db *sql.DB, username string) (*User, error) {
	u := &User{Username: username, EmbedConfig: DefaultEmbedConfig()}
	var totp, webauthn, theme, accent, language, recoveryCodeHash, embedConfig sql.NullString
	var quota, lastStep sql.NullInt64
	err := db.QueryRowContext(ctx, "SELECT id, password_hash, role, totp_secret, webauthn_data, storage_quota_mb, theme, accent, language, recovery_code_hash, embed_config, last_totp_step FROM users WHERE username = $1", username).
		Scan(&u.ID, &u.PasswordHash, &u.Role, &totp, &webauthn, &quota, &theme, &accent, &language, &recoveryCodeHash, &embedConfig, &lastStep)
	if err != nil {
		return nil, err
	}
	if totp.Valid {
		u.TOTPSecret = totp.String
	}
	if lastStep.Valid {
		u.LastTOTPStep = lastStep.Int64
	}
	if webauthn.Valid {
		u.WebAuthnData = webauthn.String
	}
	if quota.Valid {
		u.StorageQuotaMB = int(quota.Int64)
	}
	if theme.Valid {
		u.Theme = theme.String
	}
	if accent.Valid {
		u.Accent = accent.String
	}
	if language.Valid {
		u.Language = language.String
	}
	if recoveryCodeHash.Valid {
		u.RecoveryCodeHash = recoveryCodeHash.String
	}
	if embedConfig.Valid {
		u.EmbedConfigJSON = embedConfig.String
		u.EmbedConfig = ParseEmbedConfig(embedConfig.String)
	}
	return u, nil
}

// UpdateUserAuthData updates a user's TOTP and WebAuthn data (and resets last_totp_step when TOTP secret changes)
func UpdateUserAuthData(ctx context.Context, db *sql.DB, username, totpSecret, webAuthnData string) error {
	_, err := db.ExecContext(ctx, "UPDATE users SET totp_secret = $1, webauthn_data = $2, last_totp_step = 0 WHERE username = $3", totpSecret, webAuthnData, username)
	return err
}

// TryConsumeTOTPStep atomically records a used TOTP time-step for username only
func TryConsumeTOTPStep(ctx context.Context, db *sql.DB, username string, step int64) (bool, error) {
	res, err := db.ExecContext(ctx, "UPDATE users SET last_totp_step = $1 WHERE username = $2 AND COALESCE(last_totp_step, 0) < $1", step, username)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// UpdatePassword updates a user's password
func UpdatePassword(ctx context.Context, db *sql.DB, username, passwordHash string) error {
	_, err := db.ExecContext(ctx, "UPDATE users SET password_hash = $1 WHERE username = $2", passwordHash, username)
	return err
}

// UpdateRecoveryCode updates a user's recovery code hash
func UpdateRecoveryCode(ctx context.Context, db *sql.DB, username, recoveryCodeHash string) error {
	_, err := db.ExecContext(ctx, "UPDATE users SET recovery_code_hash = $1 WHERE username = $2", recoveryCodeHash, username)
	return err
}

// GetUserByID retrieves a user by ID
func GetUserByID(ctx context.Context, db *sql.DB, id int) (*User, error) {
	u := &User{ID: id, EmbedConfig: DefaultEmbedConfig()}
	var totp, webauthn, theme, accent, recoveryCodeHash, embedConfig sql.NullString
	var quota sql.NullInt64
	err := db.QueryRowContext(ctx, "SELECT username, password_hash, role, totp_secret, webauthn_data, storage_quota_mb, theme, accent, recovery_code_hash, embed_config FROM users WHERE id = $1", id).
		Scan(&u.Username, &u.PasswordHash, &u.Role, &totp, &webauthn, &quota, &theme, &accent, &recoveryCodeHash, &embedConfig)
	if err != nil {
		return nil, err
	}
	if totp.Valid {
		u.TOTPSecret = totp.String
	}
	if webauthn.Valid {
		u.WebAuthnData = webauthn.String
	}
	if quota.Valid {
		u.StorageQuotaMB = int(quota.Int64)
	}
	if theme.Valid {
		u.Theme = theme.String
	}
	if accent.Valid {
		u.Accent = accent.String
	}
	if recoveryCodeHash.Valid {
		u.RecoveryCodeHash = recoveryCodeHash.String
	}
	if embedConfig.Valid {
		u.EmbedConfigJSON = embedConfig.String
		u.EmbedConfig = ParseEmbedConfig(embedConfig.String)
	}
	return u, nil
}

// GetAllUsers retrieves all users
func GetAllUsers(ctx context.Context, database *sql.DB) ([]*User, error) {
	rows, err := database.QueryContext(ctx, "SELECT id, username, password_hash, role, storage_quota_mb FROM users ORDER BY id ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		u := &User{}
		var quota sql.NullInt64
		if err := rows.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &quota); err != nil {
			return nil, err
		}
		if quota.Valid {
			u.StorageQuotaMB = int(quota.Int64)
		}
		users = append(users, u)
	}
	return users, nil
}

// CreateSubuser creates a new user
func CreateSubuser(ctx context.Context, database *sql.DB, username, passwordHash string, quotaMB int) error {
	_, err := database.ExecContext(ctx, "INSERT INTO users (username, password_hash, role, storage_quota_mb) VALUES ($1, $2, 'user', $3)", username, passwordHash, quotaMB)
	return err
}

// DeleteUser deletes a user
func DeleteUser(ctx context.Context, database *sql.DB, username string) error {
	_, err := database.ExecContext(ctx, "DELETE FROM users WHERE username = $1 AND role != 'admin'", username)
	return err
}

// UpdateUserTheme updates a user's theme and accent preference
func UpdateUserTheme(ctx context.Context, db *sql.DB, username, theme, accent string) error {
	_, err := db.ExecContext(ctx, "UPDATE users SET theme = $1, accent = $2 WHERE username = $3", theme, accent, username)
	return err
}

// UpdateUserLanguage updates a user's language preference
func UpdateUserLanguage(ctx context.Context, db *sql.DB, username, language string) error {
	_, err := db.ExecContext(ctx, "UPDATE users SET language = $1 WHERE username = $2", language, username)
	return err
}

// UpdateUserEmbedConfig updates a user's personal media preview / embed configuration
func UpdateUserEmbedConfig(ctx context.Context, db *sql.DB, username string, cfg EmbedConfig) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, "UPDATE users SET embed_config = $1 WHERE username = $2", string(data), username)
	return err
}
