package db

import (
	"context"
	"database/sql"
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
	TotalReads   int64
	Reads24h     int64
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
	err := db.QueryRowContext(ctx, query, urlPath).Scan(
		&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size,
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
		query = `SELECT f.id, f.original_name, f.custom_name, f.url_path, f.size, f.is_private, f.storage_type, f.storage_path, f.user_id, f.uploaded_at, f.stats_enabled,
			COALESCE(tot.cnt, 0) AS total_reads,
			COALESCE(r24.cnt, 0) AS reads_24h
			FROM files f
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads GROUP BY file_id) tot ON tot.file_id = f.id
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads WHERE read_at >= $1 GROUP BY file_id) r24 ON r24.file_id = f.id
			WHERE f.user_id = $2 ORDER BY f.uploaded_at DESC`
		rows, err = db.QueryContext(ctx, query, cutoff, userID)
	} else {
		query = `SELECT f.id, f.original_name, f.custom_name, f.url_path, f.size, f.is_private, f.storage_type, f.storage_path, f.user_id, f.uploaded_at, f.stats_enabled,
			COALESCE(tot.cnt, 0) AS total_reads,
			COALESCE(r24.cnt, 0) AS reads_24h
			FROM files f
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads GROUP BY file_id) tot ON tot.file_id = f.id
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads WHERE read_at >= $1 GROUP BY file_id) r24 ON r24.file_id = f.id
			ORDER BY f.uploaded_at DESC`
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
	return files, nil
}

// DeleteFile removes a file record by ID and cleans up any related stats
func DeleteFile(ctx context.Context, db *sql.DB, id int) error {
	_, _ = db.ExecContext(ctx, "DELETE FROM file_reads WHERE file_id = $1", id)
	_, err := db.ExecContext(ctx, "DELETE FROM files WHERE id = $1", id)
	return err
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
		query = `SELECT f.id, f.original_name, f.custom_name, f.url_path, f.size, f.is_private, f.storage_type, f.storage_path, f.user_id, f.uploaded_at, f.stats_enabled,
			COALESCE(tot.cnt, 0) AS total_reads,
			COALESCE(r24.cnt, 0) AS reads_24h
			FROM files f
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads GROUP BY file_id) tot ON tot.file_id = f.id
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads WHERE read_at >= $1 GROUP BY file_id) r24 ON r24.file_id = f.id
			WHERE f.user_id = $2 ORDER BY f.uploaded_at DESC LIMIT $3`
		rows, err = db.QueryContext(ctx, query, cutoff, userID, limit)
	} else {
		query = `SELECT f.id, f.original_name, f.custom_name, f.url_path, f.size, f.is_private, f.storage_type, f.storage_path, f.user_id, f.uploaded_at, f.stats_enabled,
			COALESCE(tot.cnt, 0) AS total_reads,
			COALESCE(r24.cnt, 0) AS reads_24h
			FROM files f
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads GROUP BY file_id) tot ON tot.file_id = f.id
			LEFT JOIN (SELECT file_id, COUNT(*) AS cnt FROM file_reads WHERE read_at >= $1 GROUP BY file_id) r24 ON r24.file_id = f.id
			ORDER BY f.uploaded_at DESC LIMIT $2`
		rows, err = db.QueryContext(ctx, query, cutoff, limit)
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
	return files, nil
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

// RecordFileRead records a single file read event with timestamp and device type
func RecordFileRead(ctx context.Context, database *sql.DB, fileID int, deviceType string) error {
	now := time.Now().UTC()
	query := `INSERT INTO file_reads (file_id, device_type, read_at) VALUES ($1, $2, $3)`
	_, err := database.ExecContext(ctx, query, fileID, deviceType, now.Format("2006-01-02 15:04:05"))
	return err
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
		if v == "" {
			return nil
		}
		layouts := []string{
			"2006-01-02 15:04:05.999999999 -0700 MST",
			"2006-01-02 15:04:05 -0700 MST",
			"2006-01-02 15:04:05.999999999 +0000 UTC",
			"2006-01-02 15:04:05 +0000 UTC",
			time.RFC3339Nano,
			time.RFC3339,
			"2006-01-02 15:04:05.999999999-07:00",
			"2006-01-02 15:04:05-07:00",
			"2006-01-02 15:04:05.999999999",
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, v); err == nil {
				return &t
			}
		}
	case []byte:
		return parseDBTime(string(v))
	}
	return nil
}
