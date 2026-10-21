package db

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"fileline/internal/config"
)

// buildSQLiteDSN appends SQLite pragmas and _txlock=immediate safely even when rawURL already has query parameters.
func buildSQLiteDSN(rawURL string) string {
	base, rawQuery, _ := strings.Cut(rawURL, "?")
	q, _ := url.ParseQuery(rawQuery)
	existingPragmas := make(map[string]bool)
	for _, p := range q["_pragma"] {
		if name, _, ok := strings.Cut(p, "("); ok {
			existingPragmas[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	defaultPragmas := []struct {
		name string
		expr string
	}{
		{"foreign_keys", "foreign_keys(1)"},
		{"journal_mode", "journal_mode(WAL)"},
		{"synchronous", "synchronous(NORMAL)"},
		{"busy_timeout", "busy_timeout(5000)"},
	}
	for _, dp := range defaultPragmas {
		if !existingPragmas[dp.name] {
			q.Add("_pragma", dp.expr)
		}
	}
	if !q.Has("_txlock") {
		q.Set("_txlock", "immediate")
	}
	return base + "?" + q.Encode()
}

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
		dsn = buildSQLiteDSN(cfg.SQLiteURL)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", cfg.DBType)
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	// Configure connection pool based on backend concurrency characteristics
	if cfg.DBType == "sqlite" {
		if cfg.SQLiteURL == ":memory:" || strings.HasPrefix(cfg.SQLiteURL, ":memory:?") {
			// A plain ":memory:" SQLite DSN creates a distinct private in-memory DB per connection,
			// so cap the pool to 1 connection to keep schema and rows on a single shared handle.
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			db.SetConnMaxLifetime(0)
			db.SetConnMaxIdleTime(0)
		} else {
			// SQLite allows only one concurrent writer; a small pool (4) serves concurrent WAL readers while avoiding 25-way writer lock contention
			db.SetMaxOpenConns(4)
			db.SetMaxIdleConns(4)
			db.SetConnMaxLifetime(30 * time.Minute)
			db.SetConnMaxIdleTime(5 * time.Minute)
		}
	} else {
		db.SetMaxOpenConns(25)
		db.SetMaxIdleConns(10)
		db.SetConnMaxLifetime(30 * time.Minute)
		db.SetConnMaxIdleTime(5 * time.Minute)
	}
	// Verify connection
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	return db, nil
}
