package db

import (
	"context"
	"database/sql"
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
			uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`
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
			uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`
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
	} else if dbType == "postgres" {
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN totp_secret VARCHAR(255) DEFAULT ''")
		db.ExecContext(ctx, "ALTER TABLE users ADD COLUMN webauthn_data TEXT DEFAULT '[]'")
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

// CreateAdmin creates a new admin user
func CreateAdmin(ctx context.Context, db *sql.DB, username, passwordHash string) error {
	_, err := db.ExecContext(ctx, "INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'admin')", username, passwordHash)
	return err
}

type User struct {
	ID           int
	Username     string
	PasswordHash string
	Role         string
	TOTPSecret   string
	WebAuthnData string
}

// GetUserByUsername retrieves a user by username.
func GetUserByUsername(ctx context.Context, db *sql.DB, username string) (*User, error) {
	u := &User{Username: username}
	var totp, webauthn sql.NullString
	err := db.QueryRowContext(ctx, "SELECT id, password_hash, role, totp_secret, webauthn_data FROM users WHERE username = $1", username).
		Scan(&u.ID, &u.PasswordHash, &u.Role, &totp, &webauthn)
	if err != nil {
		return nil, err
	}
	if totp.Valid {
		u.TOTPSecret = totp.String
	}
	if webauthn.Valid {
		u.WebAuthnData = webauthn.String
	}
	return u, nil
}

// UpdateUserAuthData updates a user's TOTP and WebAuthn data
func UpdateUserAuthData(ctx context.Context, db *sql.DB, username, totpSecret, webAuthnData string) error {
	_, err := db.ExecContext(ctx, "UPDATE users SET totp_secret = $1, webauthn_data = $2 WHERE username = $3", totpSecret, webAuthnData, username)
	return err
}

// UpdatePassword updates a user's password
func UpdatePassword(ctx context.Context, db *sql.DB, username, passwordHash string) error {
	_, err := db.ExecContext(ctx, "UPDATE users SET password_hash = $1 WHERE username = $2", passwordHash, username)
	return err
}
