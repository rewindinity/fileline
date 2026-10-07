package db

import (
	"context"
	"testing"

	"fileline/internal/config"
)

func TestInitDB_SQLite(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	db, err := InitDB(ctx, cfg)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("expected ping to succeed, got %v", err)
	}
}

func TestInitDB_Unsupported(t *testing.T) {
	cfg := &config.Config{
		DBType: "mysql",
	}
	ctx := context.Background()
	_, err := InitDB(ctx, cfg)
	if err == nil {
		t.Fatalf("expected error for unsupported db type, got nil")
	}
}
