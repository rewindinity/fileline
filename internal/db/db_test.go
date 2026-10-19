package db

import (
	"context"
	"fmt"
	"strings"
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

func TestPerf03_QueryPlansAndIndexes(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	database, err := InitDB(ctx, cfg)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()

	if err := Migrate(ctx, database, "sqlite"); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	explainPlan := func(q string, args ...any) string {
		rows, err := database.QueryContext(ctx, "EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			t.Fatalf("EXPLAIN QUERY PLAN failed for %q: %v", q, err)
		}
		defer rows.Close()
		var details string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatalf("Scan explain row failed: %v", err)
			}
			details += detail + "\n"
		}
		return details
	}

	// 1. GetRecentFiles (user-filtered) must use idx_files_user_uploaded and idx_file_reads_file_at, with NO temp B-tree sort or full file_reads scan
	recentUserQuery := `WITH page AS (
		SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled
		FROM files WHERE user_id = $1 ORDER BY uploaded_at DESC LIMIT $2
	)
	SELECT page.id, page.original_name, page.custom_name, page.url_path, page.size, page.is_private, page.storage_type, page.storage_path, page.user_id, page.uploaded_at, page.stats_enabled,
		(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id) AS total_reads,
		(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id AND r.read_at >= $3) AS reads_24h
	FROM page ORDER BY page.uploaded_at DESC`
	plan1 := explainPlan(recentUserQuery, 1, 10, "2026-10-17 00:00:00")
	t.Logf("GetRecentFiles (userID=1) plan:\n%s", plan1)
	if !containsAll(plan1, "idx_files_user_uploaded", "idx_file_reads_file_at") {
		t.Errorf("expected plan to use idx_files_user_uploaded and idx_file_reads_file_at, got:\n%s", plan1)
	}
	if containsAny(plan1, "SCAN file_reads", "USE TEMP B-TREE") {
		t.Errorf("unexpected full scan or temp B-tree in GetRecentFiles plan:\n%s", plan1)
	}

	// 2. GetRecentFiles (admin / all users) must use idx_files_uploaded and idx_file_reads_file_at
	recentAllQuery := `WITH page AS (
		SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled
		FROM files ORDER BY uploaded_at DESC LIMIT $1
	)
	SELECT page.id, page.original_name, page.custom_name, page.url_path, page.size, page.is_private, page.storage_type, page.storage_path, page.user_id, page.uploaded_at, page.stats_enabled,
		(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id) AS total_reads,
		(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id AND r.read_at >= $2) AS reads_24h
	FROM page ORDER BY page.uploaded_at DESC`
	plan2 := explainPlan(recentAllQuery, 10, "2026-10-17 00:00:00")
	t.Logf("GetRecentFiles (admin) plan:\n%s", plan2)
	if !containsAll(plan2, "idx_files_uploaded", "idx_file_reads_file_at") {
		t.Errorf("expected admin plan to use idx_files_uploaded and idx_file_reads_file_at, got:\n%s", plan2)
	}
	if containsAny(plan2, "SCAN file_reads", "USE TEMP B-TREE") {
		t.Errorf("unexpected full scan or temp B-tree in admin GetRecentFiles plan:\n%s", plan2)
	}

	// 3. GetUserTotalStorage must use idx_files_user_uploaded instead of scanning files
	plan3 := explainPlan("SELECT SUM(size) FROM files WHERE user_id = $1", 1)
	t.Logf("GetUserTotalStorage plan:\n%s", plan3)
	if !containsAll(plan3, "idx_files_user_uploaded") {
		t.Errorf("expected GetUserTotalStorage to use idx_files_user_uploaded, got:\n%s", plan3)
	}
}

func TestPerf04_SQLiteDSNAndBatchInsert(t *testing.T) {
	// Verify buildSQLiteDSN preserves existing query params and sets busy_timeout and _txlock=immediate
	dsn := buildSQLiteDSN("file:test.db?mode=rwc&cache=shared")
	if !containsAll(dsn, "mode=rwc", "cache=shared", "busy_timeout%285000%29", "_txlock=immediate") {
		t.Errorf("unexpected DSN from buildSQLiteDSN: %s", dsn)
	}
	// Ensure only one '?' in DSN
	qCount := 0
	for i := 0; i < len(dsn); i++ {
		if dsn[i] == '?' {
			qCount++
		}
	}
	if qCount != 1 {
		t.Errorf("expected exactly 1 '?' in DSN %q, got %d", dsn, qCount)
	}

	// Verify RecordFileReadsBatch inserts all events atomically
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	database, err := InitDB(ctx, cfg)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()
	if err := Migrate(ctx, database, "sqlite"); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}
	if err := InsertFile(ctx, database, &File{
		OriginalName: "batch.bin",
		URLPath:      "batch-bin",
		Size:         512,
		StorageType:  "local",
		StoragePath:  "BATCHKEY",
		UserID:       1,
		StatsEnabled: true,
	}); err != nil {
		t.Fatalf("InsertFile failed: %v", err)
	}
	f, err := GetFileByURL(ctx, database, "batch-bin")
	if err != nil {
		t.Fatalf("GetFileByURL failed: %v", err)
	}

	now := time.Now().UTC()
	events := make([]ReadEvent, 250)
	for i := range events {
		dev := "pc"
		if i%2 == 0 {
			dev = "mobile"
		}
		events[i] = ReadEvent{FileID: f.ID, DeviceType: dev, ReadAt: now}
	}
	if err := RecordFileReadsBatch(ctx, database, events); err != nil {
		t.Fatalf("RecordFileReadsBatch failed: %v", err)
	}

	st, err := GetFileStats(ctx, database, f.ID)
	if err != nil {
		t.Fatalf("GetFileStats failed: %v", err)
	}
	if st.TotalReads != 250 || st.Reads24h != 250 {
		t.Fatalf("TotalReads=%d Reads24h=%d, want 250", st.TotalReads, st.Reads24h)
	}
	if st.Mobile.Count != 125 || st.PC.Count != 125 {
		t.Fatalf("Mobile=%d PC=%d, want 125 each", st.Mobile.Count, st.PC.Count)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !containsStr(s, sub) {
			return false
		}
	}
	return true
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if containsStr(s, sub) {
			return true
		}
	}
	return false
}

func containsStr(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexStr(s, sub) >= 0)
}

func indexStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// BenchmarkPerf03_SeededDashboardQueries compares the legacy full-table-materialization query
// against the new indexed CTE query on a seeded SQLite dataset (2,000 files, 100,000 file_reads).
func BenchmarkPerf03_SeededDashboardQueries(b *testing.B) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	database, err := InitDB(ctx, cfg)
	if err != nil {
		b.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()
	if err := Migrate(ctx, database, "sqlite"); err != nil {
		b.Fatalf("Migrate failed: %v", err)
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		b.Fatalf("BeginTx failed: %v", err)
	}
	fileStmt, err := tx.PrepareContext(ctx, `INSERT INTO files (original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled) VALUES ($1, '', $2, 4096, 0, 'local', $3, $4, $5, 1)`)
	if err != nil {
		b.Fatalf("Prepare file insert: %v", err)
	}
	baseTime := time.Now().UTC().Add(-48 * time.Hour)
	for i := 1; i <= 2000; i++ {
		uid := (i % 20) + 1
		ts := baseTime.Add(time.Duration(i) * time.Second).Format("2006-01-02 15:04:05")
		urlP := "u-" + time.Duration(i).String()
		if _, err := fileStmt.ExecContext(ctx, "file.bin", urlP, urlP, uid, ts); err != nil {
			b.Fatalf("Exec file insert: %v", err)
		}
	}
	fileStmt.Close()

	readStmt, err := tx.PrepareContext(ctx, `INSERT INTO file_reads (file_id, device_type, read_at) VALUES ($1, 'pc', $2)`)
	if err != nil {
		b.Fatalf("Prepare read insert: %v", err)
	}
	recentTS := time.Now().UTC().Add(-2 * time.Hour).Format("2006-01-02 15:04:05")
	oldTS := time.Now().UTC().Add(-72 * time.Hour).Format("2006-01-02 15:04:05")
	for i := 0; i < 100000; i++ {
		fid := (i % 2000) + 1
		ts := recentTS
		if i%2 == 0 {
			ts = oldTS
		}
		if _, err := readStmt.ExecContext(ctx, fid, ts); err != nil {
			b.Fatalf("Exec read insert: %v", err)
		}
	}
	readStmt.Close()
	if err := tx.Commit(); err != nil {
		b.Fatalf("Commit seed failed: %v", err)
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")

	b.Run("LegacyFullScan_GetRecentFiles", func(b *testing.B) {
		legacyQuery := `SELECT f.id, f.original_name, f.custom_name, f.url_path, f.size, f.is_private, f.storage_type, f.storage_path, f.user_id, f.uploaded_at, f.stats_enabled,
			COALESCE(tot.cnt, 0) AS total_reads,
			COALESCE(r24.cnt, 0) AS reads_24h
			FROM files f
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads GROUP BY file_id) tot ON tot.file_id = f.id
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads WHERE read_at >= $1 GROUP BY file_id) r24 ON r24.file_id = f.id
			WHERE f.user_id = $2 ORDER BY f.uploaded_at DESC LIMIT $3`
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			rows, err := database.QueryContext(ctx, legacyQuery, cutoff, 5, 10)
			if err != nil {
				b.Fatalf("legacy query failed: %v", err)
			}
			for rows.Next() {
				var f File
				_ = rows.Scan(&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size, &f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt, &f.StatsEnabled, &f.TotalReads, &f.Reads24h)
			}
			rows.Close()
		}
	})

	b.Run("OptimizedCTE_GetRecentFiles", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			files, err := GetRecentFiles(ctx, database, 10, 5)
			if err != nil || len(files) != 10 {
				b.Fatalf("GetRecentFiles failed: err=%v len=%d", err, len(files))
			}
		}
	})

	b.Run("Indexed_GetUserTotalStorage", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			total, err := GetUserTotalStorage(ctx, database, 5)
			if err != nil || total <= 0 {
				b.Fatalf("GetUserTotalStorage failed: err=%v total=%d", err, total)
			}
		}
	})
}

func BenchmarkPerf04_SingleVsBatchReads(b *testing.B) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	database, err := InitDB(ctx, cfg)
	if err != nil {
		b.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()
	if err := Migrate(ctx, database, "sqlite"); err != nil {
		b.Fatalf("Migrate failed: %v", err)
	}

	b.Run("SingleInsert_100Events", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for j := 0; j < 100; j++ {
				if err := RecordFileRead(ctx, database, 1, "pc"); err != nil {
					b.Fatalf("RecordFileRead: %v", err)
				}
			}
		}
	})

	b.Run("BatchInsert_100Events", func(b *testing.B) {
		events := make([]ReadEvent, 100)
		now := time.Now().UTC()
		for j := range events {
			events[j] = ReadEvent{FileID: 1, DeviceType: "pc", ReadAt: now}
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := RecordFileReadsBatch(ctx, database, events); err != nil {
				b.Fatalf("RecordFileReadsBatch: %v", err)
			}
		}
	})
}

func TestPerf07_GetAllUsersTotalStorage(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	database, err := InitDB(ctx, cfg)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()
	if err := Migrate(ctx, database, "sqlite"); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	for i := 1; i <= 5; i++ {
		uname := fmt.Sprintf("subuser_%d", i)
		if err := CreateSubuser(ctx, database, uname, "secret_hash", 100); err != nil {
			t.Fatalf("CreateSubuser failed: %v", err)
		}
	}

	// Insert files with distinct sizes for users 1..4 (user 5 has 0 files)
	expectedSizes := map[int]int64{
		1: 1024,
		2: 2048,
		3: 4096,
		4: 8192,
		5: 0,
	}

	for uid, size := range expectedSizes {
		if size > 0 {
			if err := InsertFile(ctx, database, &File{
				OriginalName: fmt.Sprintf("u%d.bin", uid),
				URLPath:      fmt.Sprintf("u%d-path", uid),
				Size:         size,
				StorageType:  "local",
				StoragePath:  fmt.Sprintf("key-%d", uid),
				UserID:       uid,
			}); err != nil {
				t.Fatalf("InsertFile failed: %v", err)
			}
		}
	}

	// 1. GetAllUsersTotalStorage returns exact storage totals in a single grouped query
	totals, err := GetAllUsersTotalStorage(ctx, database)
	if err != nil {
		t.Fatalf("GetAllUsersTotalStorage failed: %v", err)
	}
	for uid, wantSize := range expectedSizes {
		if got := totals[uid]; got != wantSize {
			t.Errorf("user %d storage = %d, want %d", uid, got, wantSize)
		}
	}

	// 2. GetAllUsers excludes password_hash from memory
	users, err := GetAllUsers(ctx, database)
	if err != nil {
		t.Fatalf("GetAllUsers failed: %v", err)
	}
	if len(users) != 5 {
		t.Fatalf("GetAllUsers count = %d, want 5", len(users))
	}
	for _, u := range users {
		if u.PasswordHash != "" {
			t.Errorf("user %q password_hash leaked into memory: %q", u.Username, u.PasswordHash)
		}
	}
}

func TestPerf07_GetFilesPagePaginationAndSearch(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	database, err := InitDB(ctx, cfg)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()
	if err := Migrate(ctx, database, "sqlite"); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	const totalFiles = 75
	baseTime := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	// Seed 75 files with descending timestamps
	for i := 1; i <= totalFiles; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Minute).Format("2006-01-02 15:04:05")
		name := fmt.Sprintf("file_%03d.txt", i)
		if i == 42 {
			name = "special_secret_document.pdf"
		}
		_, err := database.ExecContext(ctx,
			`INSERT INTO files (original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled)
			VALUES ($1, '', $2, $3, 0, 'local', $4, 1, $5, 0)`,
			name, fmt.Sprintf("file-%03d", i), int64(i*100), fmt.Sprintf("key-%03d", i), ts)
		if err != nil {
			t.Fatalf("insert seeded file %d failed: %v", i, err)
		}
	}

	// 1. Keyset pagination over 75 files in pages of 30
	seenIDs := make(map[int]bool)
	var cursorStr string
	pageSize := 30
	pageCount := 0

	for {
		pageCount++
		opts := FilePageOpts{
			UserID: 1,
			Limit:  pageSize,
		}
		if cursorStr != "" {
			cTS, cID, err := DecodeCursor(cursorStr)
			if err != nil {
				t.Fatalf("DecodeCursor failed: %v", err)
			}
			opts.CursorTS = &cTS
			opts.CursorID = cID
		}

		page, err := GetFilesPage(ctx, database, opts)
		if err != nil {
			t.Fatalf("GetFilesPage page %d failed: %v", pageCount, err)
		}

		for _, f := range page.Files {
			if seenIDs[f.ID] {
				t.Fatalf("duplicate file ID %d returned in page %d", f.ID, pageCount)
			}
			seenIDs[f.ID] = true
		}

		if pageCount == 1 {
			if len(page.Files) != 30 || !page.HasNext || page.NextCursor == "" {
				t.Fatalf("page 1: len=%d, HasNext=%v, NextCursor=%q", len(page.Files), page.HasNext, page.NextCursor)
			}
		} else if pageCount == 2 {
			if len(page.Files) != 30 || !page.HasNext || page.NextCursor == "" {
				t.Fatalf("page 2: len=%d, HasNext=%v, NextCursor=%q", len(page.Files), page.HasNext, page.NextCursor)
			}
		} else if pageCount == 3 {
			if len(page.Files) != 15 || page.HasNext || page.NextCursor != "" {
				t.Fatalf("page 3: len=%d, HasNext=%v, NextCursor=%q", len(page.Files), page.HasNext, page.NextCursor)
			}
			break
		}
		cursorStr = page.NextCursor
	}

	if len(seenIDs) != totalFiles {
		t.Fatalf("total unique files seen across pages = %d, want %d", len(seenIDs), totalFiles)
	}

	// 2. Server-side search filter
	searchPage, err := GetFilesPage(ctx, database, FilePageOpts{
		UserID: 1,
		Limit:  10,
		Search: "special_secret",
	})
	if err != nil {
		t.Fatalf("search GetFilesPage failed: %v", err)
	}
	if len(searchPage.Files) != 1 || searchPage.Files[0].OriginalName != "special_secret_document.pdf" {
		t.Fatalf("expected 1 search result 'special_secret_document.pdf', got %+v", searchPage.Files)
	}
}

func TestPerf07_GetFilesPageQueryPlan(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	database, err := InitDB(ctx, cfg)
	if err != nil {
		t.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()
	if err := Migrate(ctx, database, "sqlite"); err != nil {
		t.Fatalf("Migrate failed: %v", err)
	}

	explainPlan := func(q string, args ...any) string {
		rows, err := database.QueryContext(ctx, "EXPLAIN QUERY PLAN "+q, args...)
		if err != nil {
			t.Fatalf("EXPLAIN QUERY PLAN failed for %q: %v", q, err)
		}
		defer rows.Close()
		var details string
		for rows.Next() {
			var id, parent, notused int
			var detail string
			if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
				t.Fatalf("Scan explain row failed: %v", err)
			}
			details += detail + "\n"
		}
		return details
	}

	// 1. User-filtered keyset pagination query plan must use idx_files_user_uploaded with NO temp B-tree sort
	userQuery := `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled
FROM files WHERE user_id = $1 AND (uploaded_at < $2 OR (uploaded_at = $2 AND id < $3)) ORDER BY uploaded_at DESC, id DESC LIMIT 50`
	userPlan := explainPlan(userQuery, 1, "2026-10-18 12:00:00", 100)
	t.Logf("User keyset plan:\n%s", userPlan)
	if !containsAll(userPlan, "idx_files_user_uploaded") {
		t.Errorf("expected plan to use idx_files_user_uploaded, got:\n%s", userPlan)
	}
	if containsAny(userPlan, "SCAN files", "USE TEMP B-TREE") {
		t.Errorf("unexpected full scan or temp B-tree in keyset pagination plan:\n%s", userPlan)
	}

	// 2. Global keyset pagination query plan must use idx_files_uploaded with NO temp B-tree sort
	globalQuery := `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled
FROM files WHERE (uploaded_at < $1 OR (uploaded_at = $1 AND id < $2)) ORDER BY uploaded_at DESC, id DESC LIMIT 50`
	globalPlan := explainPlan(globalQuery, "2026-10-18 12:00:00", 100)
	t.Logf("Global keyset plan:\n%s", globalPlan)
	if !containsAll(globalPlan, "idx_files_uploaded") {
		t.Errorf("expected plan to use idx_files_uploaded, got:\n%s", globalPlan)
	}
	if containsAny(globalPlan, "SCAN files", "USE TEMP B-TREE") {
		t.Errorf("unexpected full scan or temp B-tree in global keyset plan:\n%s", globalPlan)
	}
}

func BenchmarkPerf07_SubusersStorageAggregation(b *testing.B) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	ctx := context.Background()
	database, err := InitDB(ctx, cfg)
	if err != nil {
		b.Fatalf("InitDB failed: %v", err)
	}
	defer database.Close()
	if err := Migrate(ctx, database, "sqlite"); err != nil {
		b.Fatalf("Migrate failed: %v", err)
	}

	const numUsers = 50
	for i := 1; i <= numUsers; i++ {
		uname := fmt.Sprintf("bench_user_%d", i)
		_ = CreateSubuser(ctx, database, uname, "hash", 100)
		for j := 1; j <= 5; j++ {
			_ = InsertFile(ctx, database, &File{
				OriginalName: fmt.Sprintf("u%d_f%d.bin", i, j),
				URLPath:      fmt.Sprintf("u%d-f%d", i, j),
				Size:         int64(i * j * 1024),
				StorageType:  "local",
				StoragePath:  fmt.Sprintf("k-%d-%d", i, j),
				UserID:       i,
			})
		}
	}

	allUsers, err := GetAllUsers(ctx, database)
	if err != nil || len(allUsers) != numUsers {
		b.Fatalf("GetAllUsers failed: %v", err)
	}

	b.Run("SingleGroupedQuery", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			totals, err := GetAllUsersTotalStorage(ctx, database)
			if err != nil || len(totals) != numUsers {
				b.Fatalf("GetAllUsersTotalStorage failed: %v", err)
			}
			for _, u := range allUsers {
				_ = totals[u.ID]
			}
		}
	})

	b.Run("NPlusOneLoopBaseline", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for _, u := range allUsers {
				total, err := GetUserTotalStorage(ctx, database, u.ID)
				if err != nil || total <= 0 {
					b.Fatalf("GetUserTotalStorage failed: %v", err)
				}
			}
		}
	})
}

func TestParseDBTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	// nil & empty checks
	if parseDBTime(nil) != nil {
		t.Errorf("expected nil for nil input")
	}
	if parseDBTime("") != nil {
		t.Errorf("expected nil for empty string")
	}
	if parseDBTime([]byte{}) != nil {
		t.Errorf("expected nil for empty []byte")
	}
	if parseDBTime(12345) != nil {
		t.Errorf("expected nil for non-string/time type")
	}

	// time.Time & *time.Time
	if pt := parseDBTime(now); pt == nil || !pt.Equal(now) {
		t.Errorf("failed to parse time.Time value")
	}
	if pt := parseDBTime(&now); pt == nil || !pt.Equal(now) {
		t.Errorf("failed to parse *time.Time value")
	}

	// standard SQLite format "YYYY-MM-DD HH:MM:SS"
	sFormatted := now.Format("2006-01-02 15:04:05")
	pt := parseDBTime(sFormatted)
	if pt == nil || !pt.Equal(now) {
		t.Errorf("failed to parse standard SQLite format %q", sFormatted)
	}

	// []byte standard format
	pt = parseDBTime([]byte(sFormatted))
	if pt == nil || !pt.Equal(now) {
		t.Errorf("failed to parse []byte SQLite format %q", sFormatted)
	}

	// RFC3339 format
	rfcFormatted := now.Format(time.RFC3339)
	pt = parseDBTime(rfcFormatted)
	if pt == nil || !pt.Equal(now) {
		t.Errorf("failed to parse RFC3339 format %q", rfcFormatted)
	}

	// RFC3339Nano format
	nanoNow := time.Now().UTC()
	nanoFormatted := nanoNow.Format(time.RFC3339Nano)
	pt = parseDBTime(nanoFormatted)
	if pt == nil || !pt.Equal(nanoNow) {
		t.Errorf("failed to parse RFC3339Nano format %q", nanoFormatted)
	}

	// Invalid string returns nil
	if parseDBTime("invalid-datetime-string") != nil {
		t.Errorf("expected nil for invalid date string")
	}
}

func BenchmarkParseDBTime(b *testing.B) {
	tsSQLite := "2026-10-19 14:30:00"
	tsRFC := "2026-10-19T14:30:00Z"

	b.Run("SQLiteFormat_FastPath", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pt := parseDBTime(tsSQLite)
			if pt == nil {
				b.Fatal("nil time")
			}
		}
	})

	b.Run("RFC3339_FastPath", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			pt := parseDBTime(tsRFC)
			if pt == nil {
				b.Fatal("nil time")
			}
		}
	})
}

func TestTOTPEncryptionDecryption(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	encrypted, err := EncryptTOTPSecret(secret)
	if err != nil {
		t.Fatalf("EncryptTOTPSecret failed: %v", err)
	}
	if !strings.HasPrefix(encrypted, totpEncryptedPrefix) {
		t.Fatalf("expected encrypted prefix %s, got: %s", totpEncryptedPrefix, encrypted)
	}
	decrypted, err := DecryptTOTPSecret(encrypted)
	if err != nil {
		t.Fatalf("DecryptTOTPSecret failed: %v", err)
	}
	if decrypted != secret {
		t.Fatalf("expected %s, got %s", secret, decrypted)
	}

	// Legacy unencrypted secret should be returned as-is
	legacy, err := DecryptTOTPSecret(secret)
	if err != nil || legacy != secret {
		t.Fatalf("expected legacy secret %s, got %s, err: %v", secret, legacy, err)
	}
}

func TestSetDataKey(t *testing.T) {
	SetDataKey("custom-configured-data-key-1234567890123456")
	secret := "MYSECRETBASE32KEY"
	encrypted, err := EncryptTOTPSecret(secret)
	if err != nil {
		t.Fatalf("EncryptTOTPSecret failed: %v", err)
	}
	decrypted, err := DecryptTOTPSecret(encrypted)
	if err != nil {
		t.Fatalf("DecryptTOTPSecret failed: %v", err)
	}
	if decrypted != secret {
		t.Fatalf("expected %s, got %s", secret, decrypted)
	}

	// Change key -> decryption of old cipher text must fail
	SetDataKey("different-key-1234567890123456789012345678")
	_, err = DecryptTOTPSecret(encrypted)
	if err == nil {
		t.Fatalf("expected decryption failure with different key, got nil")
	}

	// Restore original key -> decryption succeeds again
	SetDataKey("custom-configured-data-key-1234567890123456")
	restored, err := DecryptTOTPSecret(encrypted)
	if err != nil || restored != secret {
		t.Fatalf("expected successful decryption after restoring key, got %q, err: %v", restored, err)
	}
}
