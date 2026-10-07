package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"fileline/internal/config"
)

// InitDB initializes the database connection based on provided configuration
func InitDB(ctx context.Context, cfg *config.Config) (*sql.DB, error) {
	var driver, dsn string

	switch cfg.DBType {
	case "postgres":
		driver = "pgx"
		dsn = cfg.PostgresURL
		if dsn == "" {
			return nil, fmt.Errorf("postgres url is empty")
		}
	case "sqlite":
		driver = "sqlite"
		// SQLite standard connection string with pragmas for better performance
		dsn = cfg.SQLiteURL + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.DBType)
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxLifetime(5 * time.Minute)
	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return db, nil
}