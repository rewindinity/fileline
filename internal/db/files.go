package db

import (
	"context"
	"database/sql"
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
}

// InsertFile inserts a new file record into the database
func InsertFile(ctx context.Context, db *sql.DB, f *File) error {
	query := `INSERT INTO files (original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := db.ExecContext(ctx, query, f.OriginalName, f.CustomName, f.URLPath, f.Size, f.IsPrivate, f.StorageType, f.StoragePath, f.UserID)
	return err
}

// GetFileByURL retrieves a file by its URL path
func GetFileByURL(ctx context.Context, db *sql.DB, urlPath string) (*File, error) {
	f := &File{}
	query := `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at FROM files WHERE url_path = $1`
	err := db.QueryRowContext(ctx, query, urlPath).Scan(
		&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size,
		&f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// GetAllFiles retrieves all files
func GetAllFiles(ctx context.Context, db *sql.DB, userID int) ([]*File, error) {
	var query string
	var rows *sql.Rows
	var err error
	if userID > 0 {
		query = `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at
			FROM files WHERE user_id = $1 ORDER BY uploaded_at DESC`
		rows, err = db.QueryContext(ctx, query, userID)
	} else {
		query = `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at FROM files ORDER BY uploaded_at DESC`
		rows, err = db.QueryContext(ctx, query)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*File
	for rows.Next() {
		f := &File{}
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size, &f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

// DeleteFile removes a file record by ID
func DeleteFile(ctx context.Context, db *sql.DB, id int) error {
	_, err := db.ExecContext(ctx, "DELETE FROM files WHERE id = $1", id)
	return err
}

// GetFileByID retrieves a file by its ID
func GetFileByID(ctx context.Context, db *sql.DB, id int) (*File, error) {
	f := &File{}
	query := `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at FROM files WHERE id = $1`
	err := db.QueryRowContext(ctx, query, id).Scan(
		&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size,
		&f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// UpdateFile updates file details
func UpdateFile(ctx context.Context, db *sql.DB, id int, customName, urlPath string, isPrivate bool) error {
	_, err := db.ExecContext(ctx, "UPDATE files SET custom_name = $1, url_path = $2, is_private = $3 WHERE id = $4", customName, urlPath, isPrivate, id)
	return err
}

// GetRecentFiles retrieves the N most recent files.
func GetRecentFiles(ctx context.Context, db *sql.DB, limit, userID int) ([]*File, error) {
	var query string
	var rows *sql.Rows
	var err error
	if userID > 0 {
		query = `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at 
		FROM files WHERE user_id = $1 ORDER BY uploaded_at DESC LIMIT $2`
		rows, err = db.QueryContext(ctx, query, userID, limit)
	} else {
		query = `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, user_id, uploaded_at
		FROM files ORDER BY uploaded_at DESC LIMIT $1`
		rows, err = db.QueryContext(ctx, query, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []*File
	for rows.Next() {
		f := &File{}
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size, &f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UserID, &f.UploadedAt); err != nil {
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
