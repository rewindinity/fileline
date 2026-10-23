package server

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"fileline/internal/config"
)

func TestS3UploadFailureDoesNotFallbackToDefaultDrive(t *testing.T) {
	srv, _, _, ctxAdmin := setupTestServer(t)

	// Local default drive directory
	defaultDir := t.TempDir()
	srv.mu.Lock()
	srv.cfg.Drives = []config.Drive{
		{
			ID:               "default",
			Name:             "Default Local",
			Type:             "local",
			Enabled:          true,
			IsDefault:        true,
			LocalStoragePath: defaultDir,
		},
		{
			ID:              "s3_broken",
			Name:            "Broken S3",
			Type:            "s3",
			Enabled:         true,
			IsDefault:       false,
			S3Endpoint:      "127.0.0.1:59998", // No server listening here
			S3Region:        "us-east-1",
			S3Bucket:        "test-bucket",
			S3AccessKey:     "TEST_KEY",
			S3SecretKey:     "TEST_SECRET",
			S3Protocol:      "http",
			S3SkipSSLVerify: false,
		},
	}
	srv.cfg.DefaultDriveID = "default"
	srv.initDrives(context.Background())
	srv.mu.Unlock()

	// 1. Regular Upload to Broken S3 Drive
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", "testfile.txt")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = part.Write([]byte("important content that should not end up on local drive"))
	_ = writer.WriteField("drive_id", "s3_broken")
	_ = writer.Close()

	req := httptest.NewRequest("POST", "/upload", body).WithContext(ctxAdmin)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	// Should FAIL (e.g. 500 or 400), NOT succeed with 200 or 302
	if rr.Code == http.StatusOK || rr.Code == http.StatusFound {
		t.Fatalf("expected upload to failing S3 drive to fail, but got status %d", rr.Code)
	}

	// Verify no files were created in default local drive
	entries, err := os.ReadDir(defaultDir)
	if err != nil {
		t.Fatalf("failed to read default dir: %v", err)
	}
	if len(entries) > 0 {
		t.Fatalf("expected default storage directory to be empty, but found %d files (silent fallback occurred!)", len(entries))
	}

	// Verify no record in database
	var count int
	_ = srv.db.QueryRow("SELECT COUNT(*) FROM files").Scan(&count)
	if count != 0 {
		t.Fatalf("expected 0 files in database, got %d", count)
	}

	// 2. Chunked Upload Init to Broken S3 Drive
	initPayload := `{"file_name":"chunked.bin","total_size":10485760,"total_chunks":2,"drive_id":"s3_broken"}`
	initReq := httptest.NewRequest("POST", "/api/upload/init", strings.NewReader(initPayload)).WithContext(ctxAdmin)
	initReq.Header.Set("Content-Type", "application/json")
	initRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(initRR, initReq)

	// If CreateMultipartUpload fails on broken S3, init should fail with error
	if initRR.Code == http.StatusOK {
		t.Fatalf("expected chunked upload init on broken S3 to fail, but got status 200: %s", initRR.Body.String())
	}
}

func TestUnifiedStoragePool_SwitchPrimaryDrive(t *testing.T) {
	srv, _, _, ctxAdmin := setupTestServer(t)

	dir1 := t.TempDir()
	dir2 := t.TempDir()

	// Initial pool: Drive 1 is primary
	drivesPayload := fmt.Sprintf(`[
		{"id":"drive1","name":"Drive 1","type":"local","enabled":true,"is_default":true,"local_storage_path":%q},
		{"id":"drive2","name":"Drive 2","type":"local","enabled":true,"is_default":false,"local_storage_path":%q}
	]`, dir1, dir2)

	form := url.Values{
		"drives_json":         {drivesPayload},
		"default_drive_id":    {"drive1"},
		"max_upload_size_mb":  {"100"},
		"chunk_threshold_mb":  {"10"},
		"chunk_size_mb":       {"5"},
	}

	saveReq := httptest.NewRequest("POST", "/settings/action/storage", strings.NewReader(form.Encode())).WithContext(ctxAdmin)
	saveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	saveRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(saveRR, saveReq)
	if saveRR.Code != http.StatusFound {
		t.Fatalf("expected 302 on save, got %d", saveRR.Code)
	}

	// Upload file with default drive (drive_id = "") -> goes to Drive 1
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "file1.txt")
	_, _ = part.Write([]byte("content on drive 1"))
	_ = writer.Close()

	upReq := httptest.NewRequest("POST", "/upload", body).WithContext(ctxAdmin)
	upReq.Header.Set("Content-Type", writer.FormDataContentType())
	upRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(upRR, upReq)
	if upRR.Code != http.StatusOK && upRR.Code != http.StatusFound {
		t.Fatalf("expected upload to succeed, got %d", upRR.Code)
	}

	entries1, _ := os.ReadDir(dir1)
	entries2, _ := os.ReadDir(dir2)
	if len(entries1) != 1 || len(entries2) != 0 {
		t.Fatalf("expected file on drive 1 (len=%d) and none on drive 2 (len=%d)", len(entries1), len(entries2))
	}

	// Now switch primary drive to Drive 2!
	drivesPayload2 := fmt.Sprintf(`[
		{"id":"drive1","name":"Drive 1","type":"local","enabled":true,"is_default":false,"local_storage_path":%q},
		{"id":"drive2","name":"Drive 2","type":"local","enabled":true,"is_default":true,"local_storage_path":%q}
	]`, dir1, dir2)

	form2 := url.Values{
		"drives_json":         {drivesPayload2},
		"default_drive_id":    {"drive2"},
		"max_upload_size_mb":  {"100"},
		"chunk_threshold_mb":  {"10"},
		"chunk_size_mb":       {"5"},
	}

	saveReq2 := httptest.NewRequest("POST", "/settings/action/storage", strings.NewReader(form2.Encode())).WithContext(ctxAdmin)
	saveReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	saveRR2 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(saveRR2, saveReq2)
	if saveRR2.Code != http.StatusFound {
		t.Fatalf("expected 302 on save 2, got %d", saveRR2.Code)
	}

	// Upload next file with default drive (drive_id = "") -> goes to Drive 2!
	body2 := &bytes.Buffer{}
	writer2 := multipart.NewWriter(body2)
	part2, _ := writer2.CreateFormFile("file", "file2.txt")
	_, _ = part2.Write([]byte("content on drive 2"))
	_ = writer2.Close()

	upReq2 := httptest.NewRequest("POST", "/upload", body2).WithContext(ctxAdmin)
	upReq2.Header.Set("Content-Type", writer2.FormDataContentType())
	upRR2 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(upRR2, upReq2)
	if upRR2.Code != http.StatusOK && upRR2.Code != http.StatusFound {
		t.Fatalf("expected upload 2 to succeed, got %d", upRR2.Code)
	}

	entries1After, _ := os.ReadDir(dir1)
	entries2After, _ := os.ReadDir(dir2)
	if len(entries1After) != 1 || len(entries2After) != 1 {
		t.Fatalf("expected 1 file on drive 1 (got %d) and 1 file on drive 2 (got %d)", len(entries1After), len(entries2After))
	}
}

func TestS3SettingsProtocolAndSkipSSL(t *testing.T) {
	srv, _, _, ctxAdmin := setupTestServer(t)

	submittedDrives := `[
		{
			"id": "s3_custom",
			"name": "Custom MinIO",
			"type": "s3",
			"enabled": true,
			"is_default": true,
			"s3_endpoint": "minio.local:9000",
			"s3_region": "us-east-1",
			"s3_bucket": "my-bucket",
			"s3_access_key": "MINIO_USER",
			"s3_secret_key": "MINIO_PASS",
			"s3_protocol": "http",
			"s3_skip_ssl_verify": true
		}
	]`

	form := url.Values{
		"drives_json":         {submittedDrives},
		"default_drive_id":    {"s3_custom"},
		"max_upload_size_mb":  {"200"},
		"chunk_threshold_mb":  {"20"},
		"chunk_size_mb":       {"5"},
	}

	saveReq := httptest.NewRequest("POST", "/settings/action/storage", strings.NewReader(form.Encode())).WithContext(ctxAdmin)
	saveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	saveRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(saveRR, saveReq)

	if saveRR.Code != http.StatusFound {
		t.Fatalf("expected 302 on storage save, got %d", saveRR.Code)
	}

	srv.mu.RLock()
	drives := srv.cfg.Drives
	defID := srv.cfg.DefaultDriveID
	srv.mu.RUnlock()

	if len(drives) != 1 {
		t.Fatalf("expected 1 drive, got %d", len(drives))
	}
	d := drives[0]
	if d.ID != "s3_custom" || defID != "s3_custom" || !d.IsDefault {
		t.Errorf("expected drive to be primary, got id=%s, defID=%s, isDefault=%v", d.ID, defID, d.IsDefault)
	}
	if d.S3Protocol != "http" {
		t.Errorf("expected S3Protocol http, got %s", d.S3Protocol)
	}
	if !d.S3SkipSSLVerify {
		t.Errorf("expected S3SkipSSLVerify true, got false")
	}

	// Verify Settings Storage HTML view sanitizes secret and retains protocol & skip ssl
	getReq := httptest.NewRequest("GET", "/settings/storage", nil).WithContext(ctxAdmin)
	getRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200 on /settings/storage, got %d", getRR.Code)
	}
	body := getRR.Body.String()
	if strings.Contains(body, "MINIO_PASS") {
		t.Errorf("secret leaked into HTML output")
	}
	if !strings.Contains(body, "minio.local:9000") {
		t.Errorf("expected endpoint minio.local:9000 in HTML output")
	}
	if !strings.Contains(body, "s3_skip_ssl_verify") {
		t.Errorf("expected s3_skip_ssl_verify in HTML output")
	}
}
