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
		);`
	case "postgres":
		query = `
		CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			username VARCHAR(255) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(50) NOT NULL DEFAULT 'user'
		);`
	default:
		return fmt.Errorf("unsupported db type for migrations: %s", dbType)
	}

	_, err := db.ExecContext(ctx, query)
	return err
}

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

// GetUserByUsername retrieves a user's password hash by username
func GetUserByUsername(ctx context.Context, db *sql.DB, username string) (id int, hash string, role string, err error) {
	err = db.QueryRowContext(ctx, "SELECT id, password_hash, role FROM users WHERE username = $1", username).Scan(&id, &hash, &role)
	return
}