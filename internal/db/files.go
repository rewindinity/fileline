package db

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type File struct {
	ID           int
	OriginalName string
	CustomName   string
	URLPath      string
	Size         int64
	IsPrivate    bool
	StorageType  string
	StoragePath  string
	UserID       int
	UploadedAt   time.Time
	StatsEnabled bool
	TotalReads    int64
	Reads24h      int64
	OwnerUsername string
}

// DeviceStat holds counts and percentage breakdown for a device category
type DeviceStat struct {
	Count      int64   `json:"count"`
	Percentage float64 `json:"percentage"`
}

// FileStats holds aggregated reading stats for a file
type FileStats struct {
	TotalReads int64      `json:"total_reads"`
	Reads24h   int64      `json:"reads_24h"`
	LastReadAt *time.Time `json:"last_read_at"`
	Mobile     DeviceStat `json:"mobile"`
	PC         DeviceStat `json:"pc"`
	Tablet     DeviceStat `json:"tablet"`
	Bots       DeviceStat `json:"bots"`
	Unknown    DeviceStat `json:"unknown"`
}

// InsertFile inserts a new file record into the database
func InsertFile(ctx context.Context, db *sql.DB, f *File) error {
	query := `INSERT INTO files (original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, stats_enabled) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	_, err := db.ExecContext(ctx, query, f.OriginalName, f.CustomName, f.URLPath, f.Size, f.IsPrivate, f.StorageType, f.StoragePath, f.UserID, f.StatsEnabled)
	return err
}

// GetFileByURL retrieves a file by its URL path
func GetFileByURL(ctx context.Context, db *sql.DB, urlPath string) (*File, error) {
	f := &File{}
	query := `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled FROM files WHERE url_path = $1`
	err := db.QueryRowContext(ctx, query, urlPath).Scan(&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size,
		&f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt, &f.StatsEnabled)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// GetAllFiles retrieves all files with optional user filter and aggregated read counts
func GetAllFiles(ctx context.Context, db *sql.DB, userID int) ([]*File, error) {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	var query string
	var rows *sql.Rows
	var err error
	if userID > 0 {
		query = `WITH page AS (
			SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled
			FROM files WHERE user_id = $1 ORDER BY uploaded_at DESC
		)
		SELECT page.id, page.original_name, page.custom_name, page.url_path, page.size, page.is_private, page.storage_type, page.storage_path, page.user_id, page.uploaded_at, page.stats_enabled,
			(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id) AS total_reads,
			(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id AND r.read_at >= $2) AS reads_24h
		FROM page ORDER BY page.uploaded_at DESC`
		rows, err = db.QueryContext(ctx, query, userID, cutoff)
	} else {
		query = `WITH page AS (
			SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled
			FROM files ORDER BY uploaded_at DESC
		)
		SELECT page.id, page.original_name, page.custom_name, page.url_path, page.size, page.is_private, page.storage_type, page.storage_path, page.user_id, page.uploaded_at, page.stats_enabled,
			(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id) AS total_reads,
			(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id AND r.read_at >= $1) AS reads_24h
		FROM page ORDER BY page.uploaded_at DESC`
		rows, err = db.QueryContext(ctx, query, cutoff)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*File
	for rows.Next() {
		f := &File{}
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size, &f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt, &f.StatsEnabled, &f.TotalReads, &f.Reads24h); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// FilePageOpts defines filtering and pagination parameters for files listing.
type FilePageOpts struct {
	UserID        int
	ExcludeUserID int
	CursorTS      *time.Time
	CursorID      int
	Limit         int
	Search        string
}

// FilePage represents a paginated slice of files with keyset navigation cursors.
type FilePage struct {
	Files      []*File
	NextCursor string
	HasNext    bool
}

func formatDBTimestamp(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond() > 0 {
		return t.Format("2006-01-02 15:04:05.999999")
	}
	return t.Format("2006-01-02 15:04:05")
}

// EncodeCursor encodes a timestamp and file ID into a URL-safe keyset pagination cursor.
func EncodeCursor(uploadedAt time.Time, id int) string {
	raw := fmt.Sprintf("%s,%d", formatDBTimestamp(uploadedAt), id)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// DecodeCursor decodes a URL-safe keyset pagination cursor into its timestamp and file ID components.
func DecodeCursor(s string) (time.Time, int, error) {
	if s == "" {
		return time.Time{}, 0, errors.New("empty cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, 0, err
	}
	parts := strings.Split(string(raw), ",")
	if len(parts) != 2 {
		return time.Time{}, 0, errors.New("invalid cursor parts")
	}
	t, err := time.Parse("2006-01-02 15:04:05.999999", parts[0])
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05", parts[0])
		if err != nil {
			t, err = time.Parse(time.RFC3339Nano, parts[0])
			if err != nil {
				return time.Time{}, 0, err
			}
		}
	}
	id, err := strconv.Atoi(parts[1])
	if err != nil {
		return time.Time{}, 0, err
	}
	return t, id, nil
}

// GetFilesPage returns a paginated slice of files using keyset pagination and covering index scans.
func GetFilesPage(ctx context.Context, database *sql.DB, opts FilePageOpts) (*FilePage, error) {
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	var (
		whereClauses []string
		args         []interface{}
		argIdx       = 1
	)

	if opts.UserID > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, opts.UserID)
		argIdx++
	} else if opts.ExcludeUserID > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("user_id != $%d", argIdx))
		args = append(args, opts.ExcludeUserID)
		argIdx++
	}

	if opts.CursorTS != nil && !opts.CursorTS.IsZero() && opts.CursorID > 0 {
		tsStr := formatDBTimestamp(*opts.CursorTS)
		whereClauses = append(whereClauses, fmt.Sprintf("(uploaded_at < $%d OR (uploaded_at = $%d AND id < $%d))", argIdx, argIdx+1, argIdx+2))
		args = append(args, tsStr, tsStr, opts.CursorID)
		argIdx += 3
	}

	search := strings.TrimSpace(opts.Search)
	if search != "" {
		likePattern := "%" + search + "%"
		whereClauses = append(whereClauses, fmt.Sprintf("(original_name LIKE $%d OR custom_name LIKE $%d OR url_path LIKE $%d)", argIdx, argIdx, argIdx))
		args = append(args, likePattern)
		argIdx++
	}

	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	query := fmt.Sprintf(`SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled
						FROM files %s ORDER BY uploaded_at DESC, id DESC LIMIT %d`, whereSQL, limit+1)

	rows, err := database.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*File
	for rows.Next() {
		f := &File{}
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size, &f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt, &f.StatsEnabled); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	page := &FilePage{}
	if len(files) > limit {
		page.HasNext = true
		files = files[:limit]
		last := files[len(files)-1]
		page.NextCursor = EncodeCursor(last.UploadedAt, last.ID)
	}
	page.Files = files
	return page, nil
}

// DeleteFile removes a file record by ID and cleans up any related stats
func DeleteFile(ctx context.Context, db *sql.DB, id int) error {
	_, _ = db.ExecContext(ctx, "DELETE FROM file_reads WHERE file_id = $1", id)
	_, err := db.ExecContext(ctx, "DELETE FROM files WHERE id = $1", id)
	return err
}

// GetFilesByUserID retrieves all files owned by a user
func GetFilesByUserID(ctx context.Context, database *sql.DB, userID int) ([]*File, error) {
	rows, err := database.QueryContext(ctx, "SELECT id, original_name, custom_name, url_path, size, storage_type, storage_path FROM files WHERE user_id = $1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*File
	for rows.Next() {
		f := &File{UserID: userID}
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size, &f.StorageType, &f.StoragePath); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// GetAllStoragePaths returns a set of all storage paths (keys) currently in the database
func GetAllStoragePaths(ctx context.Context, database *sql.DB) (map[string]bool, error) {
	query := `SELECT storage_path FROM files`
	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	paths := make(map[string]bool)
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if p != "" {
			paths[p] = true
		}
	}
	return paths, rows.Err()
}

// GetFileByID retrieves a file by its ID
func GetFileByID(ctx context.Context, db *sql.DB, id int) (*File, error) {
	f := &File{}
	query := `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled FROM files WHERE id = $1`
	err := db.QueryRowContext(ctx, query, id).Scan(
		&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size,
		&f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt, &f.StatsEnabled)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// UpdateFile updates file details including stats_enabled
func UpdateFile(ctx context.Context, db *sql.DB, id int, customName, urlPath string, isPrivate bool, statsEnabled bool) error {
	_, err := db.ExecContext(ctx, "UPDATE files SET custom_name = $1, url_path = $2, is_private = $3, stats_enabled = $4 WHERE id = $5", customName, urlPath, isPrivate, statsEnabled, id)
	return err
}

// GetRecentFiles retrieves the N most recent files with aggregated read counts
func GetRecentFiles(ctx context.Context, db *sql.DB, limit, userID int) ([]*File, error) {
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	var query string
	var rows *sql.Rows
	var err error
	if userID > 0 {
		query = `WITH page AS (
			SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled
			FROM files WHERE user_id = $1 ORDER BY uploaded_at DESC LIMIT $2
		)
		SELECT page.id, page.original_name, page.custom_name, page.url_path, page.size, page.is_private, page.storage_type, page.storage_path, page.user_id, page.uploaded_at, page.stats_enabled,
			(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id) AS total_reads,
			(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id AND r.read_at >= $3) AS reads_24h
		FROM page ORDER BY page.uploaded_at DESC`
		rows, err = db.QueryContext(ctx, query, userID, limit, cutoff)
	} else {
		query = `WITH page AS (
			SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at, stats_enabled
			FROM files ORDER BY uploaded_at DESC LIMIT $1
		)
		SELECT page.id, page.original_name, page.custom_name, page.url_path, page.size, page.is_private, page.storage_type, page.storage_path, page.user_id, page.uploaded_at, page.stats_enabled,
			(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id) AS total_reads,
			(SELECT COUNT(*) FROM file_reads r WHERE r.file_id = page.id AND r.read_at >= $2) AS reads_24h
		FROM page ORDER BY page.uploaded_at DESC`
		rows, err = db.QueryContext(ctx, query, limit, cutoff)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []*File
	for rows.Next() {
		f := &File{}
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size, &f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt, &f.StatsEnabled, &f.TotalReads, &f.Reads24h); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// GetUserTotalStorage retrieves the total sum of file sizes for a specific user
func GetUserTotalStorage(ctx context.Context, database *sql.DB, userID int) (int64, error) {
	var total sql.NullInt64
	err := database.QueryRowContext(ctx, "SELECT SUM(size) FROM files WHERE user_id = $1", userID).Scan(&total)
	if err != nil {
		return 0, err
	}
	if total.Valid {
		return total.Int64, nil
	}
	return 0, nil
}

// GetAllUsersTotalStorage retrieves the total storage sum grouped by user_id in a single query
func GetAllUsersTotalStorage(ctx context.Context, database *sql.DB) (map[int]int64, error) {
	query := "SELECT user_id, COALESCE(SUM(size), 0) FROM files GROUP BY user_id"
	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	totals := make(map[int]int64)
	for rows.Next() {
		var (
			uid   int
			total int64
		)
		if err := rows.Scan(&uid, &total); err != nil {
			return nil, err
		}
		totals[uid] = total
	}
	return totals, rows.Err()
}

// ReadEvent represents a single file read event to be persisted.
type ReadEvent struct {
	FileID     int
	DeviceType string
	ReadAt     time.Time
}

// RecordFileRead records a single file read event with timestamp and device type
func RecordFileRead(ctx context.Context, database *sql.DB, fileID int, deviceType string) error {
	now := time.Now().UTC()
	query := `INSERT INTO file_reads (file_id, device_type, read_at) VALUES ($1, $2, $3)`
	_, err := database.ExecContext(ctx, query, fileID, deviceType, now.Format("2006-01-02 15:04:05"))
	return err
}

// RecordFileReadsBatch inserts multiple file read events inside a single database transaction.
func RecordFileReadsBatch(ctx context.Context, database *sql.DB, events []ReadEvent) error {
	if database == nil || len(events) == 0 {
		return nil
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO file_reads (file_id, device_type, read_at) VALUES ($1, $2, $3)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, ev := range events {
		ts := ev.ReadAt
		if ts.IsZero() {
			ts = time.Now().UTC()
		} else {
			ts = ts.UTC()
		}
		if _, err := stmt.ExecContext(ctx, ev.FileID, ev.DeviceType, ts.Format("2006-01-02 15:04:05")); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ResetFileStats deletes all recorded read statistics for a file
func ResetFileStats(ctx context.Context, database *sql.DB, fileID int) error {
	_, err := database.ExecContext(ctx, "DELETE FROM file_reads WHERE file_id = $1", fileID)
	return err
}

// GetFileStats aggregates and returns all reading statistics for a file
func GetFileStats(ctx context.Context, database *sql.DB, fileID int) (*FileStats, error) {
	stats := &FileStats{}

	var totalReads int64
	var lastReadRaw interface{}
	err := database.QueryRowContext(ctx, "SELECT COUNT(*), MAX(read_at) FROM file_reads WHERE file_id = $1", fileID).Scan(&totalReads, &lastReadRaw)
	if err != nil {
		return nil, err
	}
	stats.TotalReads = totalReads
	stats.LastReadAt = parseDBTime(lastReadRaw)
	if totalReads == 0 {
		return stats, nil
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	var reads24h int64
	err = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM file_reads WHERE file_id = $1 AND read_at >= $2", fileID, cutoff).Scan(&reads24h)
	if err != nil {
		return nil, err
	}
	stats.Reads24h = reads24h

	rows, err := database.QueryContext(ctx, "SELECT device_type, COUNT(*) FROM file_reads WHERE file_id = $1 GROUP BY device_type", fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mobileCount, pcCount, tabletCount, botCount, unknownCount int64
	for rows.Next() {
		var devType string
		var count int64
		if err := rows.Scan(&devType, &count); err != nil {
			return nil, err
		}
		switch strings.ToLower(devType) {
		case "mobile":
			mobileCount = count
		case "pc":
			pcCount = count
		case "tablet":
			tabletCount = count
		case "bot":
			botCount = count
		default:
			unknownCount += count
		}
	}

	calcPct := func(c int64) float64 {
		if totalReads == 0 {
			return 0.0
		}
		return (float64(c) / float64(totalReads)) * 100.0
	}

	stats.Mobile = DeviceStat{Count: mobileCount, Percentage: calcPct(mobileCount)}
	stats.PC = DeviceStat{Count: pcCount, Percentage: calcPct(pcCount)}
	stats.Tablet = DeviceStat{Count: tabletCount, Percentage: calcPct(tabletCount)}
	stats.Bots = DeviceStat{Count: botCount, Percentage: calcPct(botCount)}
	stats.Unknown = DeviceStat{Count: unknownCount, Percentage: calcPct(unknownCount)}

	return stats, nil
}

var dbTimeLayouts = [...]string{
	"2006-01-02 15:04:05",
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05 +0000 UTC",
	"2006-01-02 15:04:05.999999999 +0000 UTC",
	"2006-01-02 15:04:05-07:00",
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05 -0700 MST",
	"2006-01-02 15:04:05.999999999 -0700 MST",
}

func parseDBTimeString(s string) *time.Time {
	if s == "" {
		return nil
	}
	// Fast path 1: Standard SQLite format "YYYY-MM-DD HH:MM:SS" or ISO "YYYY-MM-DDTHH:MM:SS"
	if len(s) == 19 {
		switch s[10] {
		case ' ':
			if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
				return &t
			}
		case 'T':
			if t, err := time.Parse("2006-01-02T15:04:05", s); err == nil {
				return &t
			}
		}
	} else if len(s) == 20 && s[19] == 'Z' && s[10] == 'T' {
		// Fast path 2: Standard RFC3339 UTC "YYYY-MM-DDTHH:MM:SSZ"
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return &t
		}
	} else if len(s) > 20 && strings.ContainsRune(s, 'T') {
		// Fast path 3: RFC3339 with timezone offset or fractional seconds
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return &t
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return &t
		}
	}

	for _, layout := range dbTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

func parseDBTime(val interface{}) *time.Time {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case time.Time:
		return &v
	case *time.Time:
		return v
	case string:
		return parseDBTimeString(v)
	case []byte:
		if len(v) == 0 {
			return nil
		}
		return parseDBTimeString(string(v))
	}
	return nil
}
