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
	UploadedAt   time.Time
}

// InsertFile inserts a new file record into the database
func InsertFile(ctx context.Context, db *sql.DB, f *File) error {
	query := `INSERT INTO files (original_name, custom_name, url_path, size, is_private, storage_type, storage_path) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := db.ExecContext(ctx, query, f.OriginalName, f.CustomName, f.URLPath, f.Size, f.IsPrivate, f.StorageType, f.StoragePath)
	return err
}

// GetFileByURL retrieves a file by its URL path
func GetFileByURL(ctx context.Context, db *sql.DB, urlPath string) (*File, error) {
	f := &File{}
	query := `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, uploaded_at FROM files WHERE url_path = $1`
	err := db.QueryRowContext(ctx, query, urlPath).Scan(
		&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size,
		&f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UploadedAt)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// GetAllFiles retrieves all files
func GetAllFiles(ctx context.Context, db *sql.DB) ([]*File, error) {
	query := `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, uploaded_at FROM files ORDER BY uploaded_at DESC`
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []*File
	for rows.Next() {
		f := &File{}
		if err := rows.Scan(&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size, &f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UploadedAt); err != nil {
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
	query := `SELECT id, original_name, custom_name, url_path, size, is_private, storage_type, storage_path, uploaded_at FROM files WHERE id = $1`
	err := db.QueryRowContext(ctx, query, id).Scan(
		&f.ID, &f.OriginalName, &f.CustomName, &f.URLPath, &f.Size,
		&f.IsPrivate, &f.StorageType, &f.StoragePath, &f.UploadedAt)
	if err != nil {
		return nil, err
	}
	return f, nil
}
