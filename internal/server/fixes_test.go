package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func setupTestServer(t *testing.T) (*Server, *config.Config, *db.User, context.Context) {
	t.Helper()
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		JWTKey:           "test-secret-key-32-bytes-minimum-length-xyz",
		Domain:           "localhost",
		Port:             8080,
		GzipEnabled:      true,
	}

	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	passHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(passHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	admin, err := db.GetUserByUsername(context.Background(), database, "admin")
	if err != nil {
		t.Fatalf("failed to get admin: %v", err)
	}

	srv := New(cfg, database)

	// Auth context with admin user
	ctx := withUser(context.Background(), admin)

	return srv, cfg, admin, ctx
}

func Test404Layout(t *testing.T) {
	srv, _, _, ctxAdmin := setupTestServer(t)

	// 1. Guest request to non-existent file
	guestReq := httptest.NewRequest("GET", "/f/non-existent-page", nil)
	guestRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(guestRR, guestReq)

	if guestRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for guest, got %d", guestRR.Code)
	}
	guestBody := guestRR.Body.String()
	if !strings.Contains(guestBody, "404") || !strings.Contains(guestBody, "File Not Found") {
		t.Errorf("expected 404 text in body, got: %s", guestBody)
	}
	// Verify guest layout: outer auth-card exists, but NO nested inner auth-layout
	if count := strings.Count(guestBody, "class=\"auth-layout\""); count > 1 {
		t.Errorf("expected at most 1 auth-layout in guest 404, got %d (layout is nested/broken)", count)
	}

	// 2. Authenticated user request to non-existent file
	authReq := httptest.NewRequest("GET", "/f/non-existent-page", nil).WithContext(ctxAdmin)
	authRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(authRR, authReq)

	if authRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for auth user, got %d", authRR.Code)
	}
	authBody := authRR.Body.String()
	if !strings.Contains(authBody, "404") || !strings.Contains(authBody, "File Not Found") {
		t.Errorf("expected 404 text in body, got: %s", authBody)
	}
	if !strings.Contains(authBody, "app-layout") {
		t.Errorf("expected authenticated layout with app-layout, got: %s", authBody)
	}
	if !strings.Contains(authBody, "/files") || !strings.Contains(authBody, "/settings") {
		t.Errorf("expected navbar links in authenticated 404, got: %s", authBody)
	}
}

func TestMediaServingAndChromiumHeaders(t *testing.T) {
	srv, _, admin, _ := setupTestServer(t)

	// Save video payload into storage
	videoPayload := []byte("fake mp4 video stream bytes for testing headers and playback")
	storageKey := "loneliness-video.mp4"
	if err := srv.storage.Save(context.Background(), storageKey, bytes.NewReader(videoPayload)); err != nil {
		t.Fatalf("failed to save video: %v", err)
	}

	if err := db.InsertFile(context.Background(), srv.db, &db.File{
		OriginalName: "loneliness.mp4",
		URLPath:      "loneliness",
		Size:         int64(len(videoPayload)),
		StorageType:  "local",
		StoragePath:  storageKey,
		UserID:       admin.ID,
	}); err != nil {
		t.Fatalf("failed to insert file: %v", err)
	}

	// 1. Direct GET request to video file
	req := httptest.NewRequest("GET", "/f/loneliness", nil)
	rr := httptest.NewRecorder()
	srv.serveFileHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	h := rr.Header()
	if ct := h.Get("Content-Type"); ct != "video/mp4" {
		t.Errorf("expected Content-Type video/mp4, got %q", ct)
	}
	if cd := h.Get("Content-Disposition"); !strings.HasPrefix(cd, "inline;") {
		t.Errorf("expected inline Content-Disposition, got %q", cd)
	}
	if acao := h.Get("Access-Control-Allow-Origin"); acao != "*" {
		t.Errorf("expected Access-Control-Allow-Origin: *, got %q", acao)
	}
	if corp := h.Get("Cross-Origin-Resource-Policy"); corp != "cross-origin" {
		t.Errorf("expected Cross-Origin-Resource-Policy: cross-origin, got %q", corp)
	}
	if ar := h.Get("Accept-Ranges"); ar != "bytes" {
		t.Errorf("expected Accept-Ranges: bytes, got %q", ar)
	}
	// Verify CSP does NOT contain sandbox for media (which breaks Chromium)
	if csp := h.Get("Content-Security-Policy"); strings.Contains(csp, "sandbox") {
		t.Errorf("video must NOT contain sandbox in CSP (breaks Chromium native player), got: %q", csp)
	}

	// 2. Range request (Chromium media player streaming)
	rangeReq := httptest.NewRequest("GET", "/f/loneliness", nil)
	rangeReq.Header.Set("Range", "bytes=0-10")
	rangeRR := httptest.NewRecorder()
	srv.serveFileHandler(rangeRR, rangeReq)

	if rangeRR.Code != http.StatusPartialContent {
		t.Fatalf("expected 206 Partial Content, got %d", rangeRR.Code)
	}
	if cr := rangeRR.Header().Get("Content-Range"); !strings.HasPrefix(cr, "bytes 0-10/") {
		t.Errorf("expected Content-Range bytes 0-10/..., got %q", cr)
	}

	// 3. OPTIONS preflight request
	optReq := httptest.NewRequest("OPTIONS", "/f/loneliness", nil)
	optRR := httptest.NewRecorder()
	srv.serveFileHandler(optRR, optReq)

	if optRR.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content for OPTIONS, got %d", optRR.Code)
	}
	if acao := optRR.Header().Get("Access-Control-Allow-Origin"); acao != "*" {
		t.Errorf("expected Access-Control-Allow-Origin: * on OPTIONS, got %q", acao)
	}
}

func TestEditFile_URLPathDefaultAndErrorRendering(t *testing.T) {
	srv, _, admin, ctxAdmin := setupTestServer(t)

	// Save test file
	if err := srv.storage.Save(context.Background(), "my-file-key", strings.NewReader("hello")); err != nil {
		t.Fatalf("failed to save: %v", err)
	}
	file := &db.File{
		OriginalName: "My Cool Song (Remix).mp3",
		URLPath:      "initial-slug",
		Size:         5,
		StorageType:  "local",
		StoragePath:  "my-file-key",
		UserID:       admin.ID,
	}
	if err := db.InsertFile(context.Background(), srv.db, file); err != nil {
		t.Fatalf("failed to insert file: %v", err)
	}
	inserted, err := db.GetFileByURL(context.Background(), srv.db, file.URLPath)
	if err != nil {
		t.Fatalf("failed to fetch inserted file: %v", err)
	}

	// 1. Edit file with empty url_path -> should default to slug from original filename
	form := url.Values{
		"id":          {fmt.Sprintf("%d", inserted.ID)},
		"custom_name": {"New Name"},
		"url_path":    {""}, // Empty!
	}
	postReq := httptest.NewRequest("POST", "/edit", strings.NewReader(form.Encode())).WithContext(ctxAdmin)
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postRR := httptest.NewRecorder()
	srv.editFileHandler(postRR, postReq)

	if postRR.Code != http.StatusFound {
		t.Fatalf("expected 302 Found on successful edit, got %d: %s", postRR.Code, postRR.Body.String())
	}
	updated, err := db.GetFileByID(context.Background(), srv.db, inserted.ID)
	if err != nil {
		t.Fatalf("failed to fetch updated file: %v", err)
	}
	expectedSlug := slugifyURLPath(file.OriginalName)
	if updated.URLPath != expectedSlug {
		t.Errorf("expected empty url_path to default to filename slug %q, got %q", expectedSlug, updated.URLPath)
	}

	// 2. Edit file with invalid url_path -> should render HTML page with 400 Bad Request instead of raw text
	badForm := url.Values{
		"id":          {fmt.Sprintf("%d", inserted.ID)},
		"custom_name": {"New Name"},
		"url_path":    {"bad/slash/in/path"},
	}
	badReq := httptest.NewRequest("POST", "/edit", strings.NewReader(badForm.Encode())).WithContext(ctxAdmin)
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRR := httptest.NewRecorder()
	srv.editFileHandler(badRR, badReq)

	if badRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 BadRequest, got %d", badRR.Code)
	}
	badBody := badRR.Body.String()
	// Must NOT be just raw plain text "Invalid URL path characters"
	if !strings.Contains(badBody, "<!DOCTYPE html>") && !strings.Contains(badBody, "<form") {
		t.Errorf("expected HTML page rendered on error, got raw text: %s", badBody)
	}
	if !strings.Contains(badBody, "alert-error") {
		t.Errorf("expected alert-error in rendered page, got: %s", badBody)
	}
	if !strings.Contains(badBody, "Invalid URL path characters") {
		t.Errorf("expected error message in rendered HTML page, got: %s", badBody)
	}
}

func TestSettingsPasswordRoute(t *testing.T) {
	srv, _, _, ctxAdmin := setupTestServer(t)

	// 1. GET /settings/password redirects to /settings/account
	getReq := httptest.NewRequest("GET", "/settings/password", nil).WithContext(ctxAdmin)
	getRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(getRR, getReq)

	if getRR.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 SeeOther for GET /settings/password, got %d", getRR.Code)
	}
	if loc := getRR.Header().Get("Location"); loc != "/settings/account" {
		t.Errorf("expected Location /settings/account, got %q", loc)
	}

	// 2. POST /settings/password with wrong current password
	badForm := url.Values{
		"current_password": {"WrongPassword"},
		"new_password":     {"NewSecurePassword123!"},
	}
	badReq := httptest.NewRequest("POST", "/settings/password", strings.NewReader(badForm.Encode())).WithContext(ctxAdmin)
	badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(badRR, badReq)

	if badRR.Code != http.StatusFound {
		t.Fatalf("expected 302 Found, got %d", badRR.Code)
	}
	if loc := badRR.Header().Get("Location"); !strings.Contains(loc, "error=Incorrect+current+password") {
		t.Errorf("expected error in redirect location, got %q", loc)
	}

	// 3. POST /settings/password with correct current password
	goodForm := url.Values{
		"current_password": {"Password123!"},
		"new_password":     {"BrandNewPassword123!"},
	}
	goodReq := httptest.NewRequest("POST", "/settings/password", strings.NewReader(goodForm.Encode())).WithContext(ctxAdmin)
	goodReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	goodRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(goodRR, goodReq)

	if goodRR.Code != http.StatusFound {
		t.Fatalf("expected 302 Found, got %d", goodRR.Code)
	}
	if loc := goodRR.Header().Get("Location"); !strings.Contains(loc, "success=Password+updated+successfully") {
		t.Errorf("expected success in redirect location, got %q", loc)
	}

	// Verify user can log in with new password
	admin, err := db.GetUserByUsername(context.Background(), srv.db, "admin")
	if err != nil {
		t.Fatalf("failed to fetch admin: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte("BrandNewPassword123!")); err != nil {
		t.Errorf("password in database was not updated properly: %v", err)
	}
}

func TestEmbedPreview_SocialMediaVsDirectVisit(t *testing.T) {
	srv, _, admin, _ := setupTestServer(t)

	// Save test video
	storageKey := "clip-embed.mp4"
	_ = srv.storage.Save(context.Background(), storageKey, strings.NewReader("mp4 video bytes"))
	_ = db.InsertFile(context.Background(), srv.db, &db.File{
		OriginalName: "clip.mp4",
		URLPath:      "clip",
		Size:         15,
		StorageType:  "local",
		StoragePath:  storageKey,
		UserID:       admin.ID,
	})

	// Case 1: SocialMedia enabled, DirectVisit DISABLED
	// Direct human visit should get raw file directly; social media bot should get embed HTML!
	_ = db.UpdateUserEmbedConfig(context.Background(), srv.db, "admin", db.EmbedConfig{
		Enabled:     true,
		SocialMedia: true,
		DirectVisit: false,
		SiteName:    "FileLine",
		ShowTitle:   true,
	})

	// Direct browser visit (e.g. Chrome / Firefox user)
	directReq := httptest.NewRequest("GET", "/f/clip", nil)
	directReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	directRR := httptest.NewRecorder()
	srv.serveFileHandler(directRR, directReq)

	if directRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", directRR.Code)
	}
	if ct := directRR.Header().Get("Content-Type"); ct != "video/mp4" {
		t.Errorf("expected direct browser visit to serve raw file (video/mp4) when DirectVisit=false, got Content-Type: %q", ct)
	}

	// Discord Bot visit -> should get embed HTML
	discordReq := httptest.NewRequest("GET", "/f/clip", nil)
	discordReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discord.app)")
	discordRR := httptest.NewRecorder()
	srv.serveFileHandler(discordRR, discordReq)

	if discordRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for discordbot, got %d", discordRR.Code)
	}
	if ct := discordRR.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("expected discordbot to receive embed HTML, got Content-Type: %q", ct)
	}
	if !strings.Contains(discordRR.Body.String(), "og:video") {
		t.Errorf("expected og:video meta tag in embed HTML for discordbot")
	}

	// Case 2: DirectVisit ENABLED
	_ = db.UpdateUserEmbedConfig(context.Background(), srv.db, "admin", db.EmbedConfig{
		Enabled:     true,
		SocialMedia: true,
		DirectVisit: true,
		SiteName:    "FileLine",
	})
	directReq2 := httptest.NewRequest("GET", "/f/clip", nil)
	directReq2.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0")
	directRR2 := httptest.NewRecorder()
	srv.serveFileHandler(directRR2, directReq2)

	if ct := directRR2.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("expected direct browser visit to receive embed HTML when DirectVisit=true, got %q", ct)
	}
}

func TestStorageQuotaDisplay(t *testing.T) {
	srv, _, admin, _ := setupTestServer(t)

	// 1. User with quota > 0 (e.g. 100 MB)
	admin.StorageQuotaMB = 100
	ctxWithQuota := withUser(context.Background(), admin)

	req := httptest.NewRequest("GET", "/", nil).WithContext(ctxWithQuota)
	rr := httptest.NewRecorder()
	srv.dashboardHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on dashboard, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "/ 100.0 MB") {
		t.Errorf("expected dashboard to show used / limit ('/ 100.0 MB'), got:\n%s", body)
	}

	// 2. User with unlimited quota (StorageQuotaMB = 0)
	admin.StorageQuotaMB = 0
	ctxUnlimited := withUser(context.Background(), admin)

	req2 := httptest.NewRequest("GET", "/", nil).WithContext(ctxUnlimited)
	rr2 := httptest.NewRecorder()
	srv.dashboardHandler(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 on dashboard, got %d", rr2.Code)
	}
	body2 := rr2.Body.String()
	// Should show used, but NOT "/ <limit>"
	if strings.Contains(body2, "/ 0 B") || strings.Contains(body2, "/ 0.0") {
		t.Errorf("unlimited user must not display quota limit, got:\n%s", body2)
	}
}

func TestLoggerAuditActionDebugLevelAndRecoveryCodeInfo(t *testing.T) {
	var stdoutBuf, stderrBuf bytes.Buffer
	logger.SetOutput(&stdoutBuf, &stderrBuf)
	defer func() {
		logger.ResetOutput()
		logger.SetDebug(false)
	}()

	// When Debug is false (production mode):
	logger.SetDebug(false)
	stdoutBuf.Reset()

	logger.Action("User 'test' updated appearance settings (theme=global, accent=global, language=global)")
	logger.Action("User 'test' logged out")
	logger.Action("User 'test' logged in successfully via password from ::1")

	if stdoutBuf.Len() > 0 {
		t.Errorf("expected Action audit logs to be suppressed when debug=false, got:\n%s", stdoutBuf.String())
	}

	// When Debug is true:
	logger.SetDebug(true)
	stdoutBuf.Reset()

	logger.Action("User 'test' logged out")
	out := stdoutBuf.String()
	if !strings.Contains(out, "[DEBUG] [AUDIT] [ACTION] User 'test' logged out") {
		t.Errorf("expected [DEBUG] [AUDIT] [ACTION] when debug=true, got:\n%s", out)
	}

	// Password reset via recovery code is logged as [INFO]
	stdoutBuf.Reset()
	logger.Info("User 'test' successfully reset their password using recovery code from ::1 (recovery code rotated)")
	outInfo := stdoutBuf.String()
	if !strings.Contains(outInfo, "[INFO] User 'test' successfully reset their password using recovery code") {
		t.Errorf("expected recovery code reset log to have [INFO], got:\n%s", outInfo)
	}
}

func TestPrivateFile404GzipValidResponse(t *testing.T) {
	srv, _, admin, ctxAdmin := setupTestServer(t)

	// Create private file
	f := &db.File{
		OriginalName: "secret.pdf",
		URLPath:      "my-secret-doc",
		Size:         1024,
		IsPrivate:    true,
		StorageType:  "local",
		StoragePath:  "secret.pdf",
		UserID:       admin.ID,
	}
	if err := db.InsertFile(ctxAdmin, srv.db, f); err != nil {
		t.Fatalf("failed to save private file: %v", err)
	}

	// Unauthenticated guest requests private file with gzip
	req := httptest.NewRequest("GET", "/f/my-secret-doc", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for private file accessed by guest, got %d", rr.Code)
	}

	if enc := rr.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip, got %q", enc)
	}

	gzReader, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader (invalid gzip response): %v", err)
	}
	defer gzReader.Close()
	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		t.Fatalf("failed to decompress response (ERR_CONTENT_DECODING_FAILED): %v", err)
	}
	bodyStr := string(decompressed)
	if !strings.Contains(bodyStr, "404") || !strings.Contains(bodyStr, "File Not Found") {
		t.Errorf("expected 404 page content, got: %s", bodyStr)
	}
}

func TestNonExistentRouteOutsideF_404Page(t *testing.T) {
	srv, _, _, ctxAdmin := setupTestServer(t)

	// 1. Guest request to non-existent route outside /f/ (e.g. /some/random/path)
	guestReq := httptest.NewRequest("GET", "/some/random/path", nil)
	guestRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(guestRR, guestReq)

	if guestRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for guest non-existent route, got %d", guestRR.Code)
	}
	guestBody := guestRR.Body.String()
	if strings.TrimSpace(guestBody) == "404 page not found" {
		t.Fatalf("expected styled 404 HTML page, but got plain text: %q", guestBody)
	}
	if !strings.Contains(guestBody, "404") || !strings.Contains(guestBody, "File Not Found") {
		t.Errorf("expected 404 page text, got: %s", guestBody)
	}

	// 2. Authenticated user request to non-existent route
	authReq := httptest.NewRequest("GET", "/another/missing/route", nil).WithContext(ctxAdmin)
	authRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(authRR, authReq)

	if authRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for auth non-existent route, got %d", authRR.Code)
	}
	authBody := authRR.Body.String()
	if strings.TrimSpace(authBody) == "404 page not found" {
		t.Fatalf("expected styled 404 HTML page, but got plain text: %q", authBody)
	}
	if !strings.Contains(authBody, "404") || !strings.Contains(authBody, "app-layout") {
		t.Errorf("expected authenticated layout 404 page, got: %s", authBody)
	}
}

func TestEditFileInvalidURLPathRenders400WithGzip(t *testing.T) {
	srv, _, admin, ctxAdmin := setupTestServer(t)

	f := &db.File{
		OriginalName: "sample.txt",
		URLPath:      "sample-edit-target",
		Size:         100,
		IsPrivate:    false,
		StorageType:  "local",
		StoragePath:  "sample.txt",
		UserID:       admin.ID,
	}
	if err := db.InsertFile(ctxAdmin, srv.db, f); err != nil {
		t.Fatalf("failed to save file: %v", err)
	}

	savedFile, _ := db.GetFileByURL(ctxAdmin, srv.db, "sample-edit-target")

	// Submit invalid characters in url_path
	form := url.Values{
		"id":       {fmt.Sprintf("%d", savedFile.ID)},
		"url_path": {"invalid characters with spaces and symbols!@#"},
	}
	req := httptest.NewRequest("POST", "/edit", strings.NewReader(form.Encode())).WithContext(ctxAdmin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", rr.Code)
	}

	if enc := rr.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("expected Content-Encoding: gzip on 400 edit error, got %q", enc)
	}

	gzReader, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Fatalf("failed to create gzip reader for 400 response: %v", err)
	}
	defer gzReader.Close()
	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		t.Fatalf("failed to decompress 400 edit response: %v", err)
	}
	bodyStr := string(decompressed)
	if !strings.Contains(bodyStr, "Invalid URL path characters") {
		t.Errorf("expected error message in decompressed body, got: %s", bodyStr)
	}
}

func TestSubuserStorageQuotaEditing(t *testing.T) {
	srv, _, _, ctxAdmin := setupTestServer(t)

	// 1. Create a subuser
	createForm := url.Values{
		"new_username": {"subuser_test"},
		"new_password": {"ComplexPass123!"},
		"new_quota":    {"5120"},
	}
	createReq := httptest.NewRequest("POST", "/settings/users/add", strings.NewReader(createForm.Encode())).WithContext(ctxAdmin)
	createReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	createRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(createRR, createReq)

	if createRR.Code != http.StatusFound {
		t.Fatalf("expected 302 on user add, got %d", createRR.Code)
	}

	user, err := db.GetUserByUsername(context.Background(), srv.db, "subuser_test")
	if err != nil {
		t.Fatalf("failed to get created user: %v", err)
	}
	if user.StorageQuotaMB != 5120 {
		t.Fatalf("expected initial quota 5120, got %d", user.StorageQuotaMB)
	}

	// 2. Edit quota to 10240 MB
	editForm := url.Values{
		"username": {"subuser_test"},
		"quota_mb": {"10240"},
	}
	editReq := httptest.NewRequest("POST", "/settings/users/quota", strings.NewReader(editForm.Encode())).WithContext(ctxAdmin)
	editReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	editRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(editRR, editReq)

	if editRR.Code != http.StatusFound {
		t.Fatalf("expected 302 on quota update, got %d", editRR.Code)
	}

	updatedUser, err := db.GetUserByUsername(context.Background(), srv.db, "subuser_test")
	if err != nil {
		t.Fatalf("failed to get updated user: %v", err)
	}
	if updatedUser.StorageQuotaMB != 10240 {
		t.Fatalf("expected updated quota 10240, got %d", updatedUser.StorageQuotaMB)
	}

	// 3. Non-admin user cannot edit quota
	ctxSub := withUser(context.Background(), updatedUser)
	hackerReq := httptest.NewRequest("POST", "/settings/users/quota", strings.NewReader(editForm.Encode())).WithContext(ctxSub)
	hackerReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hackerRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(hackerRR, hackerReq)

	if hackerRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-admin editing quota, got %d", hackerRR.Code)
	}
}

func TestStorageSettingsNoStraySemicolons(t *testing.T) {
	srv, _, _, ctxAdmin := setupTestServer(t)

	// Add an additional drive to config
	srv.mu.Lock()
	srv.cfg.Drives = []config.Drive{
		{
			ID:               "drive_ext",
			Name:             "External Disk",
			Type:             "local",
			Enabled:          true,
			LocalStoragePath: t.TempDir(),
		},
	}
	srv.mu.Unlock()

	req := httptest.NewRequest("GET", "/settings/storage", nil).WithContext(ctxAdmin)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on storage settings, got %d", rr.Code)
	}

	body := rr.Body.String()

	// Check that none of the stray semicolons appear
	if strings.Contains(body, ";<div") {
		t.Errorf("found stray semicolon before div in rendered storage settings HTML:\n%s", body)
	}
	if strings.Contains(body, "Remove;") {
		t.Errorf("found stray semicolon in Remove button label in rendered HTML:\n%s", body)
	}
	if strings.Contains(body, ";<label") {
		t.Errorf("found stray semicolon before label in rendered HTML:\n%s", body)
	}
}

func TestMultiStorageSelectionAndActiveToggle(t *testing.T) {
	srv, _, _, ctxAdmin := setupTestServer(t)

	// 1. Configure drive with enabled: true
	srv.mu.Lock()
	srv.cfg.Drives = []config.Drive{
		{
			ID:               "backup_drive",
			Name:             "Backup Storage",
			Type:             "local",
			Enabled:          true,
			LocalStoragePath: t.TempDir(),
		},
	}
	srv.mu.Unlock()

	// Dashboard should show drive selector with Backup Storage
	dashReq := httptest.NewRequest("GET", "/", nil).WithContext(ctxAdmin)
	dashRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(dashRR, dashReq)

	if dashRR.Code != http.StatusOK {
		t.Fatalf("expected 200 on dashboard, got %d", dashRR.Code)
	}
	dashBody := dashRR.Body.String()
	if !strings.Contains(dashBody, "id=\"drive_id\"") {
		t.Fatalf("expected drive_id select in upload form on dashboard, got:\n%s", dashBody)
	}
	if !strings.Contains(dashBody, "Backup Storage") {
		t.Fatalf("expected Backup Storage option in select, got:\n%s", dashBody)
	}

	// 2. Toggle active to false via settings
	drivesPayload := `[{"id":"backup_drive","name":"Backup Storage","type":"local","enabled":false,"local_storage_path":"/tmp"}]`
	form := url.Values{
		"storage_type":        {"local"},
		"local_path":          {"/tmp"},
		"max_upload_size_mb":  {"100"},
		"chunk_threshold_mb":  {"10"},
		"chunk_size_mb":       {"5"},
		"drives_json":         {drivesPayload},
	}
	saveReq := httptest.NewRequest("POST", "/settings/action/storage", strings.NewReader(form.Encode())).WithContext(ctxAdmin)
	saveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	saveRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(saveRR, saveReq)

	if saveRR.Code != http.StatusFound {
		t.Fatalf("expected 302 on storage settings save, got %d", saveRR.Code)
	}

	srv.mu.RLock()
	drives := srv.cfg.Drives
	srv.mu.RUnlock()

	if len(drives) != 1 || drives[0].Enabled {
		t.Fatalf("expected drive to be disabled (Enabled: false), got %+v", drives)
	}

	// 3. When drive is disabled, dashboard should not show drive selector
	dashRR2 := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(dashRR2, dashReq)
	dashBody2 := dashRR2.Body.String()
	if strings.Contains(dashBody2, "id=\"drive_id\"") {
		t.Fatalf("expected drive_id select to be hidden when all drives are disabled, got:\n%s", dashBody2)
	}
}

func TestLogin2FARedirectsToDashboard(t *testing.T) {
	srv, _, _, _ := setupTestServer(t)

	// Set 2FA secret on admin
	totpSecret := "JBSWY3DPEHPK3PXP"
	if err := db.UpdateUserAuthData(context.Background(), srv.db, "admin", totpSecret, "[]"); err != nil {
		t.Fatalf("failed to update user auth data: %v", err)
	}

	// 1. Password login -> should redirect to /login/2fa
	loginForm := url.Values{
		"username": {"admin"},
		"password": {"Password123!"},
	}
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(loginRR, loginReq)

	if loginRR.Code != http.StatusFound || loginRR.Header().Get("Location") != "/login/2fa" {
		t.Fatalf("expected redirect to /login/2fa, got code %d, loc %q", loginRR.Code, loginRR.Header().Get("Location"))
	}

	var session2FACookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "2fa_session" {
			session2FACookie = c
			break
		}
	}
	if session2FACookie == nil {
		t.Fatal("expected 2fa_session cookie to be set")
	}

	// 2. Submit valid TOTP code
	code, err := totp.GenerateCode(totpSecret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	verifyForm := url.Values{"code": {code}}
	verifyReq := httptest.NewRequest("POST", "/login/2fa", strings.NewReader(verifyForm.Encode()))
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verifyReq.AddCookie(session2FACookie)
	verifyRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusFound || verifyRR.Header().Get("Location") != "/" {
		t.Fatalf("expected redirect to / after 2FA, got code %d, loc %q", verifyRR.Code, verifyRR.Header().Get("Location"))
	}

	var authSessionCookie *http.Cookie
	for _, c := range verifyRR.Result().Cookies() {
		if c.Name == "session" {
			authSessionCookie = c
			break
		}
	}
	if authSessionCookie == nil {
		t.Fatal("expected session cookie to be set after 2FA login")
	}

	// 3. Follow redirect to GET / with session cookie -> must return 200 OK (Dashboard), NOT redirect to /login
	dashReq := httptest.NewRequest("GET", "/", nil)
	dashReq.AddCookie(authSessionCookie)
	dashRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(dashRR, dashReq)

	if dashRR.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on dashboard with session cookie, but got %d (redirect location: %q)", dashRR.Code, dashRR.Header().Get("Location"))
	}
	dashBody := dashRR.Body.String()
	if !strings.Contains(dashBody, "Dashboard") {
		t.Errorf("expected dashboard content, got:\n%s", dashBody)
	}
}

func TestPasskeyLoginSessionRedirectsToDashboard(t *testing.T) {
	srv, _, admin, _ := setupTestServer(t)

	// Simulate session cookie issued by WebAuthn passkey login finish
	rec := httptest.NewRecorder()
	srv.setJWTCookie(rec, admin.Username)

	var authCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session" {
			authCookie = c
			break
		}
	}
	if authCookie == nil {
		t.Fatal("expected session cookie from setJWTCookie")
	}

	// Request GET / with the session cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(authCookie)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on dashboard for passkey session, got %d (redirect: %q)", rr.Code, rr.Header().Get("Location"))
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Dashboard") {
		t.Errorf("expected dashboard content, got:\n%s", body)
	}
	if strings.Contains(body, "404") {
		t.Errorf("did not expect 404 on dashboard with valid passkey session")
	}
}

func TestSetupPostgresTLS_HTMLRendering(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
		Port:      8080,
	}
	srv := New(cfg, nil)

	req := httptest.NewRequest("GET", "/setup", nil)
	rr := httptest.NewRecorder()
	srv.setupHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /setup GET, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `name="pg_tls"`) {
		t.Errorf("expected setup form to contain pg_tls input, got:\n%s", body)
	}
	if !strings.Contains(body, `type="checkbox"`) {
		t.Errorf("expected pg_tls to be a checkbox")
	}
	if strings.Contains(body, `id="pg_tls" name="pg_tls" checked`) {
		t.Errorf("expected pg_tls to be unchecked by default")
	}
}

func TestSetupPostgresTLS_FormHandling(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		JWTKey:           "test-secret-key-32-bytes-minimum-length-xyz",
		Domain:           "localhost",
		Port:             8080,
	}
	srv := New(cfg, nil)

	form := url.Values{}
	form.Set("db_type", "postgres")
	form.Set("pg_host", "127.0.0.1")
	form.Set("pg_port", "5433")
	form.Set("pg_user", "admin")
	form.Set("pg_password", "pass")
	form.Set("pg_db", "baza")
	form.Set("storage_type", "local")
	form.Set("local_path", tempDir)
	form.Set("username", "admin")
	form.Set("password", "Pass12345!")

	req := httptest.NewRequest("POST", "/setup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.setupHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK rendering error on /setup, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Database connection failed") {
		t.Errorf("expected Database connection failed error, got:\n%s", body)
	}
}

func TestAdminStorageScanAndImport(t *testing.T) {
	srv, cfg, admin, ctx := setupTestServer(t)

	// 1. Create a regular subuser
	hash, _ := bcrypt.GenerateFromPassword([]byte("SubuserPass1!"), bcrypt.DefaultCost)
	if err := db.CreateSubuser(ctx, srv.db, "subuser", string(hash), 0); err != nil {
		t.Fatalf("failed to create subuser: %v", err)
	}
	subuser, _ := db.GetUserByUsername(ctx, srv.db, "subuser")
	subCtx := withUser(context.Background(), subuser)

	// 2. Non-admin access rejected with 403 Forbidden
	reqScanForbidden := httptest.NewRequest("GET", "/api/admin/storage/scan", nil).WithContext(subCtx)
	rrScanForbidden := httptest.NewRecorder()
	srv.adminScanStorageHandler(rrScanForbidden, reqScanForbidden)
	if rrScanForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for non-admin scan, got %d", rrScanForbidden.Code)
	}

	reqImportForbidden := httptest.NewRequest("POST", "/api/admin/storage/import", strings.NewReader(`{"files":[]}`)).WithContext(subCtx)
	rrImportForbidden := httptest.NewRecorder()
	srv.adminImportStorageHandler(rrImportForbidden, reqImportForbidden)
	if rrImportForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for non-admin import, got %d", rrImportForbidden.Code)
	}

	// 3. Admin scans when storage is clean -> 0 files
	reqScan1 := httptest.NewRequest("GET", "/api/admin/storage/scan", nil).WithContext(ctx)
	rrScan1 := httptest.NewRecorder()
	srv.adminScanStorageHandler(rrScan1, reqScan1)
	if rrScan1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin scan, got %d", rrScan1.Code)
	}
	var scanRes1 struct {
		Success bool              `json:"success"`
		Files   []ScannedFileView `json:"files"`
	}
	if err := json.NewDecoder(rrScan1.Body).Decode(&scanRes1); err != nil {
		t.Fatalf("failed to decode scan response: %v", err)
	}
	if len(scanRes1.Files) != 0 {
		t.Fatalf("expected 0 scanned files, got %d", len(scanRes1.Files))
	}

	// 4. Simulate FTP / direct upload to local storage
	ftpFilePath := filepath.Join(cfg.LocalStoragePath, "duzy-plik.zip")
	zipPayload := []byte("PK\x03\x04large zip archive content bytes 1234567890")
	if err := os.WriteFile(ftpFilePath, zipPayload, 0640); err != nil {
		t.Fatalf("failed to write simulated FTP file: %v", err)
	}

	// Also write a hidden file that should be ignored
	_ = os.WriteFile(filepath.Join(cfg.LocalStoragePath, ".hidden_file"), []byte("hidden"), 0640)

	// Scan again -> finds duzy-plik.zip
	reqScan2 := httptest.NewRequest("GET", "/api/admin/storage/scan", nil).WithContext(ctx)
	rrScan2 := httptest.NewRecorder()
	srv.adminScanStorageHandler(rrScan2, reqScan2)
	if rrScan2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin scan, got %d", rrScan2.Code)
	}
	var scanRes2 struct {
		Success bool              `json:"success"`
		Files   []ScannedFileView `json:"files"`
	}
	if err := json.NewDecoder(rrScan2.Body).Decode(&scanRes2); err != nil {
		t.Fatalf("failed to decode scan response: %v", err)
	}
	if len(scanRes2.Files) != 1 {
		t.Fatalf("expected 1 scanned file, got %d", len(scanRes2.Files))
	}
	if scanRes2.Files[0].Key != "duzy-plik.zip" || scanRes2.Files[0].Size != int64(len(zipPayload)) {
		t.Fatalf("unexpected scanned file: %+v", scanRes2.Files[0])
	}

	// 5. Admin imports duzy-plik.zip
	importPayload := fmt.Sprintf(`{"files":[{"drive_id":%q,"key":"duzy-plik.zip"}]}`, scanRes2.Files[0].DriveID)
	reqImport := httptest.NewRequest("POST", "/api/admin/storage/import", strings.NewReader(importPayload)).WithContext(ctx)
	rrImport := httptest.NewRecorder()
	srv.adminImportStorageHandler(rrImport, reqImport)
	if rrImport.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for import, got %d (body: %s)", rrImport.Code, rrImport.Body.String())
	}
	var importRes struct {
		Success  bool     `json:"success"`
		Imported int      `json:"imported"`
		Failed   int      `json:"failed"`
		Errors   []string `json:"errors"`
	}
	if err := json.NewDecoder(rrImport.Body).Decode(&importRes); err != nil {
		t.Fatalf("failed to decode import response: %v", err)
	}
	if !importRes.Success || importRes.Imported != 1 || importRes.Failed != 0 {
		t.Fatalf("unexpected import result: %+v", importRes)
	}

	// 6. Verify file renamed on disk (duzy-plik.zip is gone, random storageKey exists)
	if _, err := os.Stat(ftpFilePath); !os.IsNotExist(err) {
		t.Fatalf("expected original duzy-plik.zip to be renamed on storage, but it still exists")
	}

	// 7. Verify DB record exists and matches
	f, err := db.GetFileByURL(ctx, srv.db, "duzy-plik.zip")
	if err != nil {
		t.Fatalf("failed to retrieve imported file by url_path: %v", err)
	}
	if f.OriginalName != "duzy-plik.zip" {
		t.Errorf("expected OriginalName 'duzy-plik.zip', got %q", f.OriginalName)
	}
	if f.Size != int64(len(zipPayload)) {
		t.Errorf("expected Size %d, got %d", len(zipPayload), f.Size)
	}
	if f.StoragePath == "" || f.StoragePath == "duzy-plik.zip" {
		t.Errorf("expected opaque randomized StoragePath, got %q", f.StoragePath)
	}
	if f.UserID != admin.ID {
		t.Errorf("expected file owner to be admin %d, got %d", admin.ID, f.UserID)
	}

	// 8. Subsequent scan returns 0 unindexed files
	reqScan3 := httptest.NewRequest("GET", "/api/admin/storage/scan", nil).WithContext(ctx)
	rrScan3 := httptest.NewRecorder()
	srv.adminScanStorageHandler(rrScan3, reqScan3)
	var scanRes3 struct {
		Files []ScannedFileView `json:"files"`
	}
	_ = json.NewDecoder(rrScan3.Body).Decode(&scanRes3)
	if len(scanRes3.Files) != 0 {
		t.Fatalf("expected 0 unindexed files after import, got %d", len(scanRes3.Files))
	}

	// 9. Verify file can be served via /f/
	reqServe := httptest.NewRequest("GET", "/f/"+f.URLPath, nil)
	rrServe := httptest.NewRecorder()
	srv.serveFileHandler(rrServe, reqServe)
	if rrServe.Code != http.StatusOK {
		t.Fatalf("expected 200 OK serving imported file, got %d", rrServe.Code)
	}
	if !bytes.Equal(rrServe.Body.Bytes(), zipPayload) {
		t.Fatalf("served body mismatch for imported file")
	}
}

func TestAdminTestS3Handler(t *testing.T) {
	srv, _, admin, ctx := setupTestServer(t)

	// Mock S3 HTTP server
	mockS3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Mock-Fail") == "true" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// Return 200 OK for S3 HeadBucket / ListObjects
		w.WriteHeader(http.StatusOK)
	}))
	defer mockS3.Close()

	endpoint := strings.TrimPrefix(mockS3.URL, "http://")

	// 1. Unauthenticated / Non-admin request
	reqUnauth := httptest.NewRequest("POST", "/api/admin/storage/test_s3", strings.NewReader(`{}`))
	rrUnauth := httptest.NewRecorder()
	srv.adminTestS3Handler(rrUnauth, reqUnauth)
	if rrUnauth.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for unauthenticated user, got %d", rrUnauth.Code)
	}

	// 2. Admin request with missing bucket
	reqEmptyBucket := httptest.NewRequest("POST", "/api/admin/storage/test_s3", strings.NewReader(`{"s3_bucket": ""}`)).WithContext(ctx)
	rrEmptyBucket := httptest.NewRecorder()
	srv.adminTestS3Handler(rrEmptyBucket, reqEmptyBucket)
	if rrEmptyBucket.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for empty bucket, got %d", rrEmptyBucket.Code)
	}

	// 3. Admin request to successful mock S3 endpoint
	payloadSuccess := fmt.Sprintf(`{
		"s3_endpoint": %q,
		"s3_region": "us-east-1",
		"s3_bucket": "test-bucket",
		"s3_access_key": "dummy",
		"s3_secret_key": "dummy",
		"s3_protocol": "http",
		"s3_skip_ssl_verify": true
	}`, endpoint)

	reqSuccess := httptest.NewRequest("POST", "/api/admin/storage/test_s3", strings.NewReader(payloadSuccess)).WithContext(ctx)
	rrSuccess := httptest.NewRecorder()
	srv.adminTestS3Handler(rrSuccess, reqSuccess)
	if rrSuccess.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from test_s3, got %d: %s", rrSuccess.Code, rrSuccess.Body.String())
	}

	var resSuccess struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(rrSuccess.Body).Decode(&resSuccess); err != nil {
		t.Fatalf("failed to parse test_s3 response: %v", err)
	}
	if !resSuccess.Success {
		t.Errorf("expected success: true, got false with error: %s", resSuccess.Error)
	}

	// 4. Admin request with existing drive secret borrowing
	srv.mu.Lock()
	srv.cfg.Drives = []config.Drive{
		{
			ID:          "s3_drive_1",
			Name:        "S3 Backup",
			Type:        "s3",
			S3Endpoint:  endpoint,
			S3Region:    "us-east-1",
			S3Bucket:    "test-bucket",
			S3AccessKey: "key-from-cfg",
			S3SecretKey: "secret-from-cfg",
			S3Protocol:  "http",
		},
	}
	srv.mu.Unlock()

	payloadBorrowSecret := fmt.Sprintf(`{
		"drive_id": "s3_drive_1",
		"s3_endpoint": %q,
		"s3_region": "us-east-1",
		"s3_bucket": "test-bucket",
		"s3_access_key": "key-from-cfg",
		"s3_secret_key": "",
		"s3_protocol": "http",
		"s3_skip_ssl_verify": true
	}`, endpoint)

	reqBorrow := httptest.NewRequest("POST", "/api/admin/storage/test_s3", strings.NewReader(payloadBorrowSecret)).WithContext(ctx)
	rrBorrow := httptest.NewRecorder()
	srv.adminTestS3Handler(rrBorrow, reqBorrow)
	if rrBorrow.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from test_s3 borrowing secret, got %d: %s", rrBorrow.Code, rrBorrow.Body.String())
	}
	var resBorrow struct {
		Success bool `json:"success"`
	}
	_ = json.NewDecoder(rrBorrow.Body).Decode(&resBorrow)
	if !resBorrow.Success {
		t.Errorf("expected success: true when borrowing secret from cfg")
	}

	// 5. Admin request to failing S3 endpoint
	payloadFail := `{
		"s3_endpoint": "127.0.0.1:1",
		"s3_region": "us-east-1",
		"s3_bucket": "test-bucket",
		"s3_protocol": "http"
	}`
	reqFail := httptest.NewRequest("POST", "/api/admin/storage/test_s3", strings.NewReader(payloadFail)).WithContext(ctx)
	rrFail := httptest.NewRecorder()
	srv.adminTestS3Handler(rrFail, reqFail)
	var resFail struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	_ = json.NewDecoder(rrFail.Body).Decode(&resFail)
	if resFail.Success {
		t.Errorf("expected success: false for invalid endpoint")
	}
	if resFail.Error == "" {
		t.Errorf("expected error message for invalid endpoint")
	}
	_ = admin
}

func TestSettingsAppearanceLogoErrorAlert(t *testing.T) {
	srv, _, _, ctx := setupTestServer(t)

	// Simulate requesting settings/appearance with logo size error in URL query
	errorMsg := "Logo file exceeds maximum allowed size (5 MB)"
	req := httptest.NewRequest("GET", "/settings/appearance?error="+url.QueryEscape(errorMsg), nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	srv.settingsAppearanceHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "alert alert-error") {
		t.Errorf("expected response to contain alert alert-error div")
	}
	if !strings.Contains(body, errorMsg) {
		t.Errorf("expected response to contain %q, body had: %s", errorMsg, body)
	}
}

func TestAdminFilesSwitchOwnAndOthers(t *testing.T) {
	srv, _, admin, ctx := setupTestServer(t)

	// Create subuser 'bob'
	subuserHash, _ := bcrypt.GenerateFromPassword([]byte("BobPass123!"), bcrypt.MinCost)
	if err := db.CreateSubuser(ctx, srv.db, "bob", string(subuserHash), 100); err != nil {
		t.Fatalf("failed to create subuser bob: %v", err)
	}

	bob, err := db.GetUserByUsername(ctx, srv.db, "bob")
	if err != nil {
		t.Fatalf("failed to fetch user bob: %v", err)
	}

	// Insert admin files
	adminFile1 := &db.File{
		OriginalName: "admin_report.pdf",
		URLPath:      "admin-report",
		Size:         1024,
		StorageType:  "local",
		StoragePath:  "admin_report.pdf",
		UserID:       admin.ID,
	}
	adminFile2 := &db.File{
		OriginalName: "admin_backup.zip",
		URLPath:      "admin-backup",
		Size:         2048,
		StorageType:  "local",
		StoragePath:  "admin_backup.zip",
		UserID:       admin.ID,
	}
	if err := db.InsertFile(ctx, srv.db, adminFile1); err != nil {
		t.Fatalf("failed to insert adminFile1: %v", err)
	}
	if err := db.InsertFile(ctx, srv.db, adminFile2); err != nil {
		t.Fatalf("failed to insert adminFile2: %v", err)
	}

	// Insert bob files
	bobFile1 := &db.File{
		OriginalName: "bob_notes.txt",
		URLPath:      "bob-notes",
		Size:         512,
		StorageType:  "local",
		StoragePath:  "bob_notes.txt",
		UserID:       bob.ID,
	}
	bobFile2 := &db.File{
		OriginalName: "bob_photo.jpg",
		URLPath:      "bob-photo",
		Size:         4096,
		StorageType:  "local",
		StoragePath:  "bob_photo.jpg",
		UserID:       bob.ID,
	}
	if err := db.InsertFile(ctx, srv.db, bobFile1); err != nil {
		t.Fatalf("failed to insert bobFile1: %v", err)
	}
	if err := db.InsertFile(ctx, srv.db, bobFile2); err != nil {
		t.Fatalf("failed to insert bobFile2: %v", err)
	}

	// 1. Admin GET /files with default parameters (should show admin's own files only)
	reqDefault := httptest.NewRequest("GET", "/files", nil).WithContext(ctx)
	rrDefault := httptest.NewRecorder()
	srv.filesHandler(rrDefault, reqDefault)
	if rrDefault.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin default /files, got %d", rrDefault.Code)
	}
	bodyDefault := rrDefault.Body.String()
	if !strings.Contains(bodyDefault, "admin_report.pdf") || !strings.Contains(bodyDefault, "admin_backup.zip") {
		t.Errorf("expected admin files to be present in default view")
	}
	if strings.Contains(bodyDefault, "bob_notes.txt") || strings.Contains(bodyDefault, "bob_photo.jpg") {
		t.Errorf("expected other users' files to NOT be present in default view")
	}
	if !strings.Contains(bodyDefault, "segmented-switch") {
		t.Errorf("expected segmented-switch in admin files page")
	}
	if !strings.Contains(bodyDefault, `class="segmented-switch-btn active"`) {
		t.Errorf("expected active segmented-switch button")
	}

	// 2. Admin GET /files?filter=own explicitly
	reqOwn := httptest.NewRequest("GET", "/files?filter=own", nil).WithContext(ctx)
	rrOwn := httptest.NewRecorder()
	srv.filesHandler(rrOwn, reqOwn)
	if rrOwn.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /files?filter=own, got %d", rrOwn.Code)
	}
	bodyOwn := rrOwn.Body.String()
	if !strings.Contains(bodyOwn, "admin_report.pdf") {
		t.Errorf("expected admin files in /files?filter=own")
	}
	if strings.Contains(bodyOwn, "bob_notes.txt") {
		t.Errorf("expected no bob files in /files?filter=own")
	}

	// 3. Admin GET /files?filter=others (should show only other users' files and display uploader)
	reqOthers := httptest.NewRequest("GET", "/files?filter=others", nil).WithContext(ctx)
	rrOthers := httptest.NewRecorder()
	srv.filesHandler(rrOthers, reqOthers)
	if rrOthers.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin /files?filter=others, got %d", rrOthers.Code)
	}
	bodyOthers := rrOthers.Body.String()
	if strings.Contains(bodyOthers, "admin_report.pdf") || strings.Contains(bodyOthers, "admin_backup.zip") {
		t.Errorf("expected admin files to NOT be present in others view")
	}
	if !strings.Contains(bodyOthers, "bob_notes.txt") || !strings.Contains(bodyOthers, "bob_photo.jpg") {
		t.Errorf("expected other users' files in others view")
	}
	// Verify uploader username 'bob' is displayed in the table
	if !strings.Contains(bodyOthers, "bob") {
		t.Errorf("expected uploader username 'bob' in others view table")
	}

	// 4. Admin search within others
	reqSearchOthers := httptest.NewRequest("GET", "/files?filter=others&q=bob_notes", nil).WithContext(ctx)
	rrSearchOthers := httptest.NewRecorder()
	srv.filesHandler(rrSearchOthers, reqSearchOthers)
	bodySearchOthers := rrSearchOthers.Body.String()
	if !strings.Contains(bodySearchOthers, "bob_notes.txt") {
		t.Errorf("expected matching file bob_notes.txt in filtered search")
	}
	if strings.Contains(bodySearchOthers, "bob_photo.jpg") {
		t.Errorf("expected non-matching file bob_photo.jpg to be filtered out")
	}
	if !strings.Contains(bodySearchOthers, `name="filter" value="others"`) {
		t.Errorf("expected hidden filter input with value 'others' in search form")
	}

	// 5. Regular subuser bob visiting /files (must only see bob's files, no switch)
	ctxBob := withUser(context.Background(), bob)
	reqBob := httptest.NewRequest("GET", "/files?filter=others", nil).WithContext(ctxBob)
	rrBob := httptest.NewRecorder()
	srv.filesHandler(rrBob, reqBob)
	bodyBob := rrBob.Body.String()
	if strings.Contains(bodyBob, "admin_report.pdf") {
		t.Errorf("regular user bob must NOT see admin files even with filter=others")
	}
	if !strings.Contains(bodyBob, "bob_notes.txt") {
		t.Errorf("regular user bob must see their own files")
	}
	if strings.Contains(bodyBob, "segmented-switch") {
		t.Errorf("regular user bob must NOT see segmented-switch")
	}
}

func TestDeleteSubuserDeletesFilesAndDisplaysID(t *testing.T) {
	srv, cfg, admin, ctxAdmin := setupTestServer(t)

	// 1. Create subuser 'charlie'
	passHash, _ := bcrypt.GenerateFromPassword([]byte("Charlie123!"), bcrypt.MinCost)
	if err := db.CreateSubuser(ctxAdmin, srv.db, "charlie", string(passHash), 50); err != nil {
		t.Fatalf("failed to create subuser charlie: %v", err)
	}

	charlie, err := db.GetUserByUsername(ctxAdmin, srv.db, "charlie")
	if err != nil {
		t.Fatalf("failed to fetch user charlie: %v", err)
	}

	// 2. Write physical files and insert DB records for charlie
	charliePath1 := "charlie_file1.txt"
	charliePath2 := "charlie_file2.txt"
	fullPath1 := filepath.Join(cfg.LocalStoragePath, charliePath1)
	fullPath2 := filepath.Join(cfg.LocalStoragePath, charliePath2)
	_ = os.WriteFile(fullPath1, []byte("hello charlie file 1"), 0644)
	_ = os.WriteFile(fullPath2, []byte("hello charlie file 2"), 0644)

	charlieFile1 := &db.File{
		OriginalName: "charlie_file1.txt",
		URLPath:      "charlie-1",
		Size:         20,
		StorageType:  "local",
		StoragePath:  charliePath1,
		UserID:       charlie.ID,
	}
	charlieFile2 := &db.File{
		OriginalName: "charlie_file2.txt",
		URLPath:      "charlie-2",
		Size:         20,
		StorageType:  "local",
		StoragePath:  charliePath2,
		UserID:       charlie.ID,
	}
	if err := db.InsertFile(ctxAdmin, srv.db, charlieFile1); err != nil {
		t.Fatalf("failed to insert charlieFile1: %v", err)
	}
	if err := db.InsertFile(ctxAdmin, srv.db, charlieFile2); err != nil {
		t.Fatalf("failed to insert charlieFile2: %v", err)
	}

	// Also insert an admin file that should remain intact
	adminPath := "admin_keep.txt"
	fullAdminPath := filepath.Join(cfg.LocalStoragePath, adminPath)
	_ = os.WriteFile(fullAdminPath, []byte("admin keep data"), 0644)
	adminFile := &db.File{
		OriginalName: "admin_keep.txt",
		URLPath:      "admin-keep",
		Size:         15,
		StorageType:  "local",
		StoragePath:  adminPath,
		UserID:       admin.ID,
	}
	if err := db.InsertFile(ctxAdmin, srv.db, adminFile); err != nil {
		t.Fatalf("failed to insert adminFile: %v", err)
	}

	// 3. Test that /settings/subusers displays user IDs
	reqSubusers := httptest.NewRequest("GET", "/settings/subusers", nil).WithContext(ctxAdmin)
	rrSubusers := httptest.NewRecorder()
	srv.settingsSubusersHandler(rrSubusers, reqSubusers)
	if rrSubusers.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /settings/subusers, got %d", rrSubusers.Code)
	}
	bodySubusers := rrSubusers.Body.String()
	// Check for ID header and user ID badge
	if !strings.Contains(bodySubusers, ">ID<") {
		t.Errorf("expected ID column header in subusers table")
	}
	expectedCharlieBadge := fmt.Sprintf("#%d", charlie.ID)
	if !strings.Contains(bodySubusers, expectedCharlieBadge) {
		t.Errorf("expected charlie's ID badge %q in subusers table", expectedCharlieBadge)
	}

	// 4. Admin deletes charlie via POST /settings/users/delete
	form := url.Values{}
	form.Set("username", "charlie")
	reqDel := httptest.NewRequest("POST", "/settings/users/delete", strings.NewReader(form.Encode())).WithContext(ctxAdmin)
	reqDel.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrDel := httptest.NewRecorder()
	srv.deleteUserHandler(rrDel, reqDel)
	if rrDel.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect after deleting user, got %d", rrDel.Code)
	}

	// 5. Verify user charlie is gone from DB
	_, err = db.GetUserByUsername(ctxAdmin, srv.db, "charlie")
	if err == nil {
		t.Errorf("expected error fetching deleted user charlie from DB")
	}

	// 6. Verify charlie's files are gone from DB
	remainingFiles, err := db.GetFilesByUserID(ctxAdmin, srv.db, charlie.ID)
	if err != nil {
		t.Fatalf("failed to query files by user ID: %v", err)
	}
	if len(remainingFiles) != 0 {
		t.Errorf("expected 0 files for deleted user charlie, found %d", len(remainingFiles))
	}

	// 7. Verify physical files on storage were deleted
	if _, err := os.Stat(fullPath1); !os.IsNotExist(err) {
		t.Errorf("expected charlie physical file 1 to be deleted from storage")
	}
	if _, err := os.Stat(fullPath2); !os.IsNotExist(err) {
		t.Errorf("expected charlie physical file 2 to be deleted from storage")
	}

	// 8. Verify admin file is still intact on storage and DB
	if _, err := os.Stat(fullAdminPath); err != nil {
		t.Errorf("admin file was unexpectedly removed from storage")
	}
	af, err := db.GetFileByURL(ctxAdmin, srv.db, "admin-keep")
	if err != nil || af == nil {
		t.Errorf("admin file was unexpectedly deleted from DB")
	}
}
