package db

import (
	"context"
	"testing"
	"time"

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

func TestFileStats(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	database, err := InitDB(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()

	if err := Migrate(ctx, database, "sqlite"); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Insert test file with StatsEnabled = true
	f := &File{
		OriginalName: "sample.pdf",
		CustomName:   "document",
		URLPath:      "doc123",
		Size:         1024,
		IsPrivate:    false,
		StorageType:  "local",
		StoragePath:  "local/sample.pdf",
		UserID:       1,
		StatsEnabled: true,
	}
	if err := InsertFile(ctx, database, f); err != nil {
		t.Fatalf("failed to insert file: %v", err)
	}

	fetched, err := GetFileByURL(ctx, database, "doc123")
	if err != nil {
		t.Fatalf("failed to get file by url: %v", err)
	}
	if !fetched.StatsEnabled {
		t.Fatalf("expected StatsEnabled true, got false")
	}

	// Initial stats should be zero
	stats, err := GetFileStats(ctx, database, fetched.ID)
	if err != nil {
		t.Fatalf("failed to get initial file stats: %v", err)
	}
	if stats.TotalReads != 0 || stats.Reads24h != 0 || stats.LastReadAt != nil {
		t.Fatalf("expected 0 stats, got total=%d 24h=%d lastRead=%v", stats.TotalReads, stats.Reads24h, stats.LastReadAt)
	}

	// Record reads:
	// 2 mobile, 1 pc, 1 tablet, 1 bot, 1 unknown
	devs := []string{"mobile", "mobile", "pc", "tablet", "bot", "unknown"}
	for _, d := range devs {
		if err := RecordFileRead(ctx, database, fetched.ID, d); err != nil {
			t.Fatalf("failed to record file read for %s: %v", d, err)
		}
	}

	// Also insert an old read (older than 24h)
	oldTime := time.Now().UTC().Add(-48 * time.Hour)
	_, err = database.ExecContext(ctx, "INSERT INTO file_reads (file_id, device_type, read_at) VALUES ($1, $2, $3)", fetched.ID, "pc", oldTime)
	if err != nil {
		t.Fatalf("failed to insert old read: %v", err)
	}

	stats, err = GetFileStats(ctx, database, fetched.ID)
	if err != nil {
		t.Fatalf("failed to get updated stats: %v", err)
	}

	// Total reads: 6 recent + 1 old = 7
	if stats.TotalReads != 7 {
		t.Errorf("expected 7 total reads, got %d", stats.TotalReads)
	}
	// Reads 24h: 6
	if stats.Reads24h != 6 {
		t.Errorf("expected 6 reads in 24h, got %d", stats.Reads24h)
	}
	t.Logf("stats: TotalReads=%d, Reads24h=%d, LastReadAt=%v", stats.TotalReads, stats.Reads24h, stats.LastReadAt)
	if stats.LastReadAt == nil {
		t.Errorf("expected LastReadAt to be set, got nil")
	}

	// Device counts:
	// mobile: 2
	// pc: 2 (1 recent + 1 old)
	// tablet: 1
	// bot: 1
	// unknown: 1
	if stats.Mobile.Count != 2 {
		t.Errorf("expected 2 mobile reads, got %d", stats.Mobile.Count)
	}
	if stats.PC.Count != 2 {
		t.Errorf("expected 2 pc reads, got %d", stats.PC.Count)
	}
	if stats.Tablet.Count != 1 {
		t.Errorf("expected 1 tablet read, got %d", stats.Tablet.Count)
	}
	if stats.Bots.Count != 1 {
		t.Errorf("expected 1 bot read, got %d", stats.Bots.Count)
	}
	if stats.Unknown.Count != 1 {
		t.Errorf("expected 1 unknown read, got %d", stats.Unknown.Count)
	}

	// Percentages check
	expectedMobilePct := (2.0 / 7.0) * 100.0
	if diff := stats.Mobile.Percentage - expectedMobilePct; diff < -0.01 || diff > 0.01 {
		t.Errorf("expected mobile pct ~%.2f, got %.2f", expectedMobilePct, stats.Mobile.Percentage)
	}

	// Test GetAllFiles aggregates
	allFiles, err := GetAllFiles(ctx, database, 0)
	if err != nil {
		t.Fatalf("failed to get all files: %v", err)
	}
	if len(allFiles) != 1 {
		t.Fatalf("expected 1 file, got %d", len(allFiles))
	}
	if allFiles[0].TotalReads != 7 || allFiles[0].Reads24h != 6 {
		t.Errorf("expected allFiles[0] to have total=7 24h=6, got total=%d 24h=%d", allFiles[0].TotalReads, allFiles[0].Reads24h)
	}

	// Test ResetFileStats
	if err := ResetFileStats(ctx, database, fetched.ID); err != nil {
		t.Fatalf("failed to reset file stats: %v", err)
	}

	statsAfterReset, err := GetFileStats(ctx, database, fetched.ID)
	if err != nil {
		t.Fatalf("failed to get stats after reset: %v", err)
	}
	if statsAfterReset.TotalReads != 0 || statsAfterReset.Reads24h != 0 || statsAfterReset.LastReadAt != nil {
		t.Fatalf("expected stats to be cleared after reset, got total=%d", statsAfterReset.TotalReads)
	}

	// Test UpdateFile toggle stats
	if err := UpdateFile(ctx, database, fetched.ID, "doc_updated", "doc_updated", false, false); err != nil {
		t.Fatalf("failed to update file: %v", err)
	}
	updated, _ := GetFileByID(ctx, database, fetched.ID)
	if updated.StatsEnabled {
		t.Errorf("expected StatsEnabled to be false after update")
	}

	// Delete file should delete file_reads cleanly
	if err := DeleteFile(ctx, database, fetched.ID); err != nil {
		t.Fatalf("failed to delete file: %v", err)
	}
}
