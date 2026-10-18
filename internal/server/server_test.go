package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fileline/internal/auth"
	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func TestHealthHandler(t *testing.T) {
	// Setup in-memory sqlite for testing
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	srv := New(cfg, database)
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	expected := `{"status": "ok"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v", rr.Body.String(), expected)
	}
}

func TestTOTPGenerateAndVerify(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()

	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate db: %v", err)
	}

	// Create test user
	err = db.CreateAdmin(context.Background(), database, "testuser", "hashedpw")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	srv := New(cfg, database)

	// 1. Generate 2FA
	ctx := context.WithValue(context.Background(), "username", "testuser")
	genReq := httptest.NewRequest("POST", "/settings/2fa/generate", nil).WithContext(ctx)
	genRR := httptest.NewRecorder()
	srv.totpGenerateHandler(genRR, genReq)

	if genRR.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", genRR.Code)
	}
	if ct := genRR.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %s", ct)
	}

	var genRes struct {
		Secret string `json:"secret"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(genRR.Body.Bytes(), &genRes); err != nil {
		t.Fatalf("failed to parse JSON response: %v, body: %s", err, genRR.Body.String())
	}
	if genRes.Secret == "" {
		t.Fatal("expected non-empty secret")
	}
	if !strings.HasPrefix(genRes.URL, "otpauth://totp/") {
		t.Fatalf("expected URL starting with otpauth://totp/, got %s", genRes.URL)
	}

	// 2. Verify with invalid code
	invalidForm := strings.NewReader("code=000000")
	invalidReq := httptest.NewRequest("POST", "/settings/2fa/verify", invalidForm).WithContext(ctx)
	invalidReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	invalidRR := httptest.NewRecorder()
	srv.totpVerifyHandler(invalidRR, invalidReq)

	if invalidRR.Code != http.StatusFound {
		t.Fatalf("expected redirect 302, got %d", invalidRR.Code)
	}
	if loc := invalidRR.Header().Get("Location"); loc != "/settings/account?error=Invalid+code" {
		t.Fatalf("expected redirect to /settings/account?error=Invalid+code, got %s", loc)
	}

	// 3. Verify with valid code
	validCode, err := totp.GenerateCode(genRes.Secret, time.Now())
	if err != nil {
		t.Fatalf("failed to generate valid totp code: %v", err)
	}
	validForm := strings.NewReader("code=" + validCode)
	validReq := httptest.NewRequest("POST", "/settings/2fa/verify", validForm).WithContext(ctx)
	validReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validRR := httptest.NewRecorder()
	srv.totpVerifyHandler(validRR, validReq)

	if validRR.Code != http.StatusFound {
		t.Fatalf("expected redirect 302, got %d", validRR.Code)
	}
	if loc := validRR.Header().Get("Location"); loc != "/settings/account?success=2FA+Enabled+Successfully" {
		t.Fatalf("expected redirect to /settings/account?success=2FA+Enabled+Successfully, got %s", loc)
	}

	// Check user now has TOTPSecret stored
	u, err := db.GetUserByUsername(context.Background(), database, "testuser")
	if err != nil {
		t.Fatalf("failed to fetch user: %v", err)
	}
	if u.TOTPSecret != genRes.Secret {
		t.Fatalf("expected stored TOTPSecret %s, got %s", genRes.Secret, u.TOTPSecret)
	}
}

func TestInternalErrorGenericResponse(t *testing.T) {
	var stdoutBuf, stderrBuf bytes.Buffer
	logger.SetOutput(&stdoutBuf, &stderrBuf)
	defer logger.ResetOutput()

	srv := &Server{}

	// 1. Plain request with text error
	req := httptest.NewRequest("GET", "/some/page", nil)
	rr := httptest.NewRecorder()
	srv.internalError(rr, req, "Failed to render template", errors.New("template syntax error at line 42"))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rr.Code)
	}
	// Verify frontend gets generic message
	body := strings.TrimSpace(rr.Body.String())
	if body != "Internal Server Error" {
		t.Errorf("expected 'Internal Server Error', got %q", body)
	}
	// Verify sensitive details NOT exposed to client
	if strings.Contains(rr.Body.String(), "template syntax error") {
		t.Errorf("internal error details leaked to client: %s", rr.Body.String())
	}
	// Verify backend console received the error
	if !strings.Contains(stderrBuf.String(), "[ERROR] Failed to render template: template syntax error at line 42") {
		t.Errorf("expected error log in stderr, got: %s", stderrBuf.String())
	}

	stderrBuf.Reset()

	// 2. JSON request (Accept: application/json)
	jsonReq := httptest.NewRequest("POST", "/settings/password", nil)
	jsonReq.Header.Set("Accept", "application/json")
	jsonRR := httptest.NewRecorder()
	srv.internalError(jsonRR, jsonReq, "Database connection failed", errors.New("pq: password authentication failed for user postgres"))

	if jsonRR.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", jsonRR.Code)
	}
	if ct := jsonRR.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}
	if jsonRR.Body.String() != `{"error": "Internal Server Error"}` {
		t.Errorf("expected generic json error, got: %s", jsonRR.Body.String())
	}
	if strings.Contains(jsonRR.Body.String(), "postgres") {
		t.Errorf("database credentials leaked to client: %s", jsonRR.Body.String())
	}
	if !strings.Contains(stderrBuf.String(), "[ERROR] Database connection failed: pq: password authentication failed") {
		t.Errorf("expected error in stderr, got: %s", stderrBuf.String())
	}
}

func TestLoggingMiddleware(t *testing.T) {
	var stdoutBuf, stderrBuf bytes.Buffer
	logger.SetOutput(&stdoutBuf, &stderrBuf)
	defer func() {
		logger.ResetOutput()
		logger.SetDebug(false)
	}()

	cfg := &config.Config{}
	srv := &Server{cfg: cfg}
	handler := srv.loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/test/middleware", nil)

	// In non-debug mode: NO HTTP logs
	logger.SetDebug(false)
	stdoutBuf.Reset()
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req)
	if strings.Contains(stdoutBuf.String(), "[HTTP]") {
		t.Errorf("expected no HTTP logs when debug is false, got: %s", stdoutBuf.String())
	}

	// In debug mode: HTTP logs present
	logger.SetDebug(true)
	stdoutBuf.Reset()
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req)
	out := stdoutBuf.String()
	if !strings.Contains(out, "[DEBUG] [HTTP] GET /test/middleware -> 200") {
		t.Errorf("expected HTTP log in debug mode, got: %s", out)
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	var stdoutBuf, stderrBuf bytes.Buffer
	logger.SetOutput(&stdoutBuf, &stderrBuf)
	defer logger.ResetOutput()

	srv := &Server{}
	handler := srv.recoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("nil pointer dereference inside secret handler")
	}))

	req := httptest.NewRequest("GET", "/panic", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "nil pointer dereference") {
		t.Fatalf("panic leaked to client: %s", rr.Body.String())
	}
	if !strings.Contains(stderrBuf.String(), "[ERROR] PANIC in HTTP handler: nil pointer dereference") {
		t.Fatalf("expected panic in stderr log, got: %s", stderrBuf.String())
	}
}

func TestPasskeyRenameAndDelete(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()

	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate db: %v", err)
	}

	err = db.CreateAdmin(context.Background(), database, "passkeyuser", "hashedpw")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	// Insert initial passkey
	credID := []byte("credential-123456")
	encodedID := base64.URLEncoding.EncodeToString(credID)
	initialPasskeys := []auth.Passkey{
		{
			Credential: webauthn.Credential{
				ID: credID,
			},
			Name: "Initial Key",
		},
	}
	pkJSON, _ := json.Marshal(initialPasskeys)
	db.UpdateUserAuthData(context.Background(), database, "passkeyuser", "", string(pkJSON))

	srv := New(cfg, database)
	ctx := context.WithValue(context.Background(), "username", "passkeyuser")

	// 1. Rename passkey to custom name
	renameBody := fmt.Sprintf(`{"id": "%s", "name": "My YubiKey"}`, encodedID)
	renameReq := httptest.NewRequest("POST", "/settings/webauthn/rename", strings.NewReader(renameBody)).WithContext(ctx)
	renameReq.Header.Set("Content-Type", "application/json")
	renameReq.Header.Set("Accept", "application/json")
	renameRR := httptest.NewRecorder()
	srv.webAuthnRenameHandler(renameRR, renameReq)

	if renameRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", renameRR.Code, renameRR.Body.String())
	}
	var res map[string]string
	if err := json.Unmarshal(renameRR.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if res["name"] != "My YubiKey" {
		t.Fatalf("expected renamed 'My YubiKey', got %s", res["name"])
	}

	// Verify in DB
	u, _ := db.GetUserByUsername(context.Background(), database, "passkeyuser")
	var savedPK []auth.Passkey
	json.Unmarshal([]byte(u.WebAuthnData), &savedPK)
	if len(savedPK) != 1 || savedPK[0].Name != "My YubiKey" {
		t.Fatalf("expected 'My YubiKey' in DB, got: %v", savedPK)
	}

	// 2. Rename with empty name -> fallback to timestamp format
	emptyRenameBody := fmt.Sprintf(`{"id": "%s", "name": "   "}`, encodedID)
	emptyReq := httptest.NewRequest("POST", "/settings/webauthn/rename", strings.NewReader(emptyRenameBody)).WithContext(ctx)
	emptyReq.Header.Set("Content-Type", "application/json")
	emptyReq.Header.Set("Accept", "application/json")
	emptyRR := httptest.NewRecorder()
	srv.webAuthnRenameHandler(emptyRR, emptyReq)

	if emptyRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", emptyRR.Code, emptyRR.Body.String())
	}
	res = nil
	json.Unmarshal(emptyRR.Body.Bytes(), &res)
	if !strings.HasPrefix(res["name"], "Passkey 20") {
		t.Fatalf("expected timestamp passkey name, got %s", res["name"])
	}

	// 3. Rename non-existent ID -> 404
	badReq := httptest.NewRequest("POST", "/settings/webauthn/rename", strings.NewReader(`{"id":"non-existent","name":"Test"}`)).WithContext(ctx)
	badReq.Header.Set("Content-Type", "application/json")
	badReq.Header.Set("Accept", "application/json")
	badRR := httptest.NewRecorder()
	srv.webAuthnRenameHandler(badRR, badReq)
	if badRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-existent passkey, got %d", badRR.Code)
	}

	// 4. Delete passkey
	delBody := fmt.Sprintf(`{"id": "%s"}`, encodedID)
	delReq := httptest.NewRequest("POST", "/settings/webauthn/delete", strings.NewReader(delBody)).WithContext(ctx)
	delReq.Header.Set("Content-Type", "application/json")
	delReq.Header.Set("Accept", "application/json")
	delRR := httptest.NewRecorder()
	srv.webAuthnDeleteHandler(delRR, delReq)

	if delRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", delRR.Code)
	}
	u, _ = db.GetUserByUsername(context.Background(), database, "passkeyuser")
	if u.WebAuthnData != "[]" {
		t.Fatalf("expected empty passkeys '[]', got: %s", u.WebAuthnData)
	}
}

func TestLogin2FAHandler(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
		JWTKey:    "test-jwt-secret-key-12345",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()

	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate db: %v", err)
	}

	totpSecret, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "FileLine",
		AccountName: "totpuser",
	})
	err = db.CreateAdmin(context.Background(), database, "totpuser", "hashedpw")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	db.UpdateUserAuthData(context.Background(), database, "totpuser", totpSecret.Secret(), "[]")

	srv := New(cfg, database)

	// Session setup
	sessionID := "test-2fa-session-xyz"
	srv.login2FAStore.Store(sessionID, "totpuser")

	// 1. GET /login/2fa with 2fa_session cookie
	getReq := httptest.NewRequest("GET", "/login/2fa", nil)
	getReq.AddCookie(&http.Cookie{Name: "2fa_session", Value: sessionID})
	getRR := httptest.NewRecorder()
	srv.login2FAHandler(getRR, getReq)

	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", getRR.Code)
	}
	body := getRR.Body.String()
	if !strings.Contains(body, "two-factor-input") || !strings.Contains(body, "name=\"code\"") {
		t.Fatalf("expected 2FA form in body, got: %s", body)
	}
	if !strings.Contains(body, "totpuser") {
		t.Fatalf("expected target username in body, got: %s", body)
	}

	// 2. POST with invalid 2FA code
	invalidForm := strings.NewReader("code=000000")
	invalidReq := httptest.NewRequest("POST", "/login/2fa", invalidForm)
	invalidReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	invalidReq.AddCookie(&http.Cookie{Name: "2fa_session", Value: sessionID})
	invalidRR := httptest.NewRecorder()
	srv.login2FAHandler(invalidRR, invalidReq)

	if invalidRR.Code != http.StatusOK {
		t.Fatalf("expected 200 OK re-rendered on error, got %d", invalidRR.Code)
	}
	invalidBody := invalidRR.Body.String()
	if !strings.Contains(invalidBody, "alert alert-error") {
		t.Fatalf("expected error alert on invalid code, got: %s", invalidBody)
	}

	// 3. POST with valid 2FA code
	validCode, _ := totp.GenerateCode(totpSecret.Secret(), time.Now())
	validForm := strings.NewReader("code=" + validCode)
	validReq := httptest.NewRequest("POST", "/login/2fa", validForm)
	validReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validReq.AddCookie(&http.Cookie{Name: "2fa_session", Value: sessionID})
	validRR := httptest.NewRecorder()
	srv.login2FAHandler(validRR, validReq)

	if validRR.Code != http.StatusFound {
		t.Fatalf("expected 302 Found redirect to dashboard, got %d", validRR.Code)
	}
	if loc := validRR.Header().Get("Location"); loc != "/" {
		t.Fatalf("expected redirect to '/', got %s", loc)
	}
	// Check JWT session cookie set
	cookies := validRR.Result().Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "session" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatalf("expected JWT session cookie to be set")
	}
}

func TestClassifyUserAgent(t *testing.T) {
	cases := []struct {
		ua       string
		expected string
	}{
		// Bots
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "bot"},
		{"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)", "bot"},
		{"Twitterbot/1.0", "bot"},
		// Tablets
		{"Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148", "tablet"},
		{"Mozilla/5.0 (Linux; Android 9; SM-T830 Build/PPR1.180610.011; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.157 Safari/537.36 tablet", "tablet"},
		// Mobile
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1", "mobile"},
		{"Mozilla/5.0 (Linux; Android 13; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36", "mobile"},
		// PC
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "pc"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "pc"},
		{"Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0", "pc"},
		// Unknown / uncategorized
		{"curl/7.68.0", "unknown"},
		{"Wget/1.20.3 (linux-gnu)", "unknown"},
		{"CustomClient/1.0", "unknown"},
		{"", "unknown"},
	}

	for _, tc := range cases {
		got := classifyUserAgent(tc.ua)
		if got != tc.expected {
			t.Errorf("classifyUserAgent(%q) = %q; want %q", tc.ua, got, tc.expected)
		}
	}
}

func TestServeFile_StatsTracking(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		JWTKey:           "test-secret",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	srv := New(cfg, database)

	// Save test content into storage
	storageKey := "sample-test-file.txt"
	if err := srv.storage.Save(context.Background(), storageKey, strings.NewReader("Hello FileLine Stats")); err != nil {
		t.Fatalf("failed to save test file to storage: %v", err)
	}

	// 1. Insert file with StatsEnabled = false
	disabledFile := &db.File{
		OriginalName: "disabled.txt",
		URLPath:      "disabled",
		Size:         20,
		IsPrivate:    false,
		StorageType:  "local",
		StoragePath:  storageKey,
		UserID:       1,
		StatsEnabled: false,
	}
	if err := db.InsertFile(context.Background(), database, disabledFile); err != nil {
		t.Fatalf("failed to insert disabled file: %v", err)
	}
	dFile, _ := db.GetFileByURL(context.Background(), database, "disabled")

	// Serve disabled file
	req1 := httptest.NewRequest("GET", "/f/disabled", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0")
	rr1 := httptest.NewRecorder()
	srv.serveFileHandler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr1.Code)
	}

	// Wait briefly for any async goroutine
	time.Sleep(50 * time.Millisecond)
	st1, _ := db.GetFileStats(context.Background(), database, dFile.ID)
	if st1.TotalReads != 0 {
		t.Errorf("expected 0 reads recorded for disabled stats file, got %d", st1.TotalReads)
	}

	// 2. Insert file with StatsEnabled = true
	enabledFile := &db.File{
		OriginalName: "enabled.txt",
		URLPath:      "enabled",
		Size:         20,
		IsPrivate:    false,
		StorageType:  "local",
		StoragePath:  storageKey,
		UserID:       1,
		StatsEnabled: true,
	}
	if err := db.InsertFile(context.Background(), database, enabledFile); err != nil {
		t.Fatalf("failed to insert enabled file: %v", err)
	}
	eFile, _ := db.GetFileByURL(context.Background(), database, "enabled")

	// Serve enabled file with iPhone User-Agent
	req2 := httptest.NewRequest("GET", "/f/enabled", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) Version/16.5 Mobile/15E148 Safari/604.1")
	rr2 := httptest.NewRecorder()
	srv.serveFileHandler(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr2.Code)
	}

	// Wait for goroutine
	time.Sleep(100 * time.Millisecond)
	st2, err := db.GetFileStats(context.Background(), database, eFile.ID)
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}
	if st2.TotalReads != 1 {
		t.Fatalf("expected 1 read recorded, got %d", st2.TotalReads)
	}
	if st2.Mobile.Count != 1 {
		t.Errorf("expected 1 mobile read, got %d", st2.Mobile.Count)
	}
	if st2.Mobile.Percentage != 100.0 {
		t.Errorf("expected 100%% mobile, got %.1f", st2.Mobile.Percentage)
	}
}

func TestEditFile_StatsToggleAndReset(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "admin", "hash"); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	srv := New(cfg, database)
	ctx := context.WithValue(context.Background(), "username", "admin")

	// 1. Create file with stats enabled
	f := &db.File{
		OriginalName: "report.pdf",
		CustomName:   "Q3 Report",
		URLPath:      "q3report",
		Size:         100,
		UserID:       1,
		StatsEnabled: true,
	}
	db.InsertFile(context.Background(), database, f)
	inserted, _ := db.GetFileByURL(context.Background(), database, "q3report")

	// Record some reads
	db.RecordFileRead(context.Background(), database, inserted.ID, "mobile")
	db.RecordFileRead(context.Background(), database, inserted.ID, "pc")
	st, _ := db.GetFileStats(context.Background(), database, inserted.ID)
	if st.TotalReads != 2 {
		t.Fatalf("expected 2 reads, got %d", st.TotalReads)
	}

	// 2. GET /edit?id=... should return 200 with Reset Statistics button rendered (since stats enabled)
	getReq := httptest.NewRequest("GET", fmt.Sprintf("/edit?id=%d", inserted.ID), nil).WithContext(ctx)
	getRR := httptest.NewRecorder()
	srv.editFileHandler(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("expected 200 on edit GET, got %d", getRR.Code)
	}
	if !strings.Contains(getRR.Body.String(), "Reset Statistics") {
		t.Errorf("expected Reset Statistics in edit html")
	}

	// 3. POST /edit with stats_enabled unchecked (deactivating stats) -> resets DB stats!
	deactForm := strings.NewReader(fmt.Sprintf("id=%d&custom_name=Q3+Report&url_path=q3report", inserted.ID))
	deactReq := httptest.NewRequest("POST", "/edit", deactForm).WithContext(ctx)
	deactReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deactRR := httptest.NewRecorder()
	srv.editFileHandler(deactRR, deactReq)
	if deactRR.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect after edit, got %d", deactRR.Code)
	}

	// Verify file stats_enabled is now false and stats were reset in DB
	up1, _ := db.GetFileByID(context.Background(), database, inserted.ID)
	if up1.StatsEnabled {
		t.Errorf("expected stats_enabled to be false")
	}
	stAfterDeact, _ := db.GetFileStats(context.Background(), database, inserted.ID)
	if stAfterDeact.TotalReads != 0 {
		t.Errorf("expected 0 reads after stats deactivation, got %d", stAfterDeact.TotalReads)
	}

	// 4. POST /edit activating stats back on (activating stats) -> resets DB stats!
	actForm := strings.NewReader(fmt.Sprintf("id=%d&custom_name=Q3+Report&url_path=q3report&stats_enabled=on", inserted.ID))
	actReq := httptest.NewRequest("POST", "/edit", actForm).WithContext(ctx)
	actReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	actRR := httptest.NewRecorder()
	srv.editFileHandler(actRR, actReq)
	if actRR.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect after edit, got %d", actRR.Code)
	}

	up2, _ := db.GetFileByID(context.Background(), database, inserted.ID)
	if !up2.StatsEnabled {
		t.Errorf("expected stats_enabled to be true")
	}

	// 5. Add reads and test manual reset (reset_stats=1)
	db.RecordFileRead(context.Background(), database, inserted.ID, "bot")
	st3, _ := db.GetFileStats(context.Background(), database, inserted.ID)
	if st3.TotalReads != 1 {
		t.Fatalf("expected 1 read before manual reset, got %d", st3.TotalReads)
	}

	resetForm := strings.NewReader(fmt.Sprintf("id=%d&custom_name=Q3+Report&url_path=q3report&stats_enabled=on&reset_stats=1", inserted.ID))
	resetReq := httptest.NewRequest("POST", "/edit", resetForm).WithContext(ctx)
	resetReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resetRR := httptest.NewRecorder()
	srv.editFileHandler(resetRR, resetReq)
	if resetRR.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect after reset, got %d", resetRR.Code)
	}
	if loc := resetRR.Header().Get("Location"); loc != fmt.Sprintf("/edit?id=%d", inserted.ID) {
		t.Errorf("expected redirect to /edit?id=%d, got %s", inserted.ID, loc)
	}

	stAfterReset, _ := db.GetFileStats(context.Background(), database, inserted.ID)
	if stAfterReset.TotalReads != 0 {
		t.Errorf("expected 0 reads after reset_stats, got %d", stAfterReset.TotalReads)
	}
}

func TestUploadHandler_StatsEnabled(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		JWTKey:           "test-secret",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "uploader", "hash"); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	srv := New(cfg, database)
	ctx := context.WithValue(context.Background(), "username", "uploader")

	// 1. Upload without stats_enabled
	var b1 bytes.Buffer
	w1 := multipart.NewWriter(&b1)
	fPart1, _ := w1.CreateFormFile("file", "file_without_stats.txt")
	fPart1.Write([]byte("content without stats"))
	w1.WriteField("url_path", "nostats")
	w1.Close()

	req1 := httptest.NewRequest("POST", "/upload", &b1).WithContext(ctx)
	req1.Header.Set("Content-Type", w1.FormDataContentType())
	rr1 := httptest.NewRecorder()
	srv.uploadHandler(rr1, req1)
	if rr1.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr1.Code)
	}

	f1, err := db.GetFileByURL(context.Background(), database, "nostats")
	if err != nil {
		t.Fatalf("failed to get uploaded file 1: %v", err)
	}
	if f1.StatsEnabled {
		t.Errorf("expected StatsEnabled to be false when not checked in upload form")
	}

	// 2. Upload with stats_enabled = on
	var b2 bytes.Buffer
	w2 := multipart.NewWriter(&b2)
	fPart2, _ := w2.CreateFormFile("file", "file_with_stats.txt")
	fPart2.Write([]byte("content with stats"))
	w2.WriteField("url_path", "withstats")
	w2.WriteField("stats_enabled", "on")
	w2.Close()

	req2 := httptest.NewRequest("POST", "/upload", &b2).WithContext(ctx)
	req2.Header.Set("Content-Type", w2.FormDataContentType())
	rr2 := httptest.NewRecorder()
	srv.uploadHandler(rr2, req2)
	if rr2.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr2.Code)
	}

	f2, err := db.GetFileByURL(context.Background(), database, "withstats")
	if err != nil {
		t.Fatalf("failed to get uploaded file 2: %v", err)
	}
	if !f2.StatsEnabled {
		t.Errorf("expected StatsEnabled to be true when explicitly checked in upload form")
	}

	// 3. Chunk upload init with stats_enabled = true
	initBody := `{"file_name": "chunked_stats.bin", "total_size": 2048, "total_chunks": 1, "stats_enabled": true, "url_path": "chunkedstats"}`
	initReq := httptest.NewRequest("POST", "/api/upload/init", strings.NewReader(initBody)).WithContext(ctx)
	initReq.Header.Set("Content-Type", "application/json")
	initRR := httptest.NewRecorder()
	srv.chunkUploadInitHandler(initRR, initReq)
	if initRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", initRR.Code)
	}
	var initRes map[string]string
	json.Unmarshal(initRR.Body.Bytes(), &initRes)
	upID := initRes["upload_id"]
	srv.chunkMu.RLock()
	chunkUploadSession := srv.chunkUploads[upID]
	srv.chunkMu.RUnlock()
	if chunkUploadSession == nil || !chunkUploadSession.StatsEnabled {
		t.Errorf("expected chunk upload session to have StatsEnabled=true")
	}
}

func TestFileStatsAPIHandler(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		JWTKey:           "test-secret",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	if err := db.CreateAdmin(context.Background(), database, "alice", "hash"); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}
	userAlice, _ := db.GetUserByUsername(context.Background(), database, "alice")
	if err := db.CreateSubuser(context.Background(), database, "bob", "hash", userAlice.ID); err != nil {
		t.Fatalf("failed to create bob: %v", err)
	}

	srv := New(cfg, database)

	fAlice := &db.File{
		UserID:       userAlice.ID,
		OriginalName: "alice_notes.pdf",
		CustomName:   "Notes",
		URLPath:      "alicenotes",
		Size:         1024,
		StoragePath:  "alice_notes.pdf",
		StorageType:  "local",
		StatsEnabled: true,
	}
	db.InsertFile(context.Background(), database, fAlice)
	fileObj, _ := db.GetFileByURL(context.Background(), database, "alicenotes")

	db.RecordFileRead(context.Background(), database, fileObj.ID, "mobile")
	db.RecordFileRead(context.Background(), database, fileObj.ID, "mobile")
	db.RecordFileRead(context.Background(), database, fileObj.ID, "pc")

	// 1. Forbidden for Bob
	ctxBob := context.WithValue(context.Background(), "username", "bob")
	reqBob := httptest.NewRequest("GET", fmt.Sprintf("/api/files/stats?id=%d", fileObj.ID), nil).WithContext(ctxBob)
	rrBob := httptest.NewRecorder()
	srv.fileStatsAPIHandler(rrBob, reqBob)
	if rrBob.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for non-owner, got %d", rrBob.Code)
	}

	// 2. Success for Alice
	ctxAlice := context.WithValue(context.Background(), "username", "alice")
	reqAlice := httptest.NewRequest("GET", fmt.Sprintf("/api/files/stats?id=%d", fileObj.ID), nil).WithContext(ctxAlice)
	rrAlice := httptest.NewRecorder()
	srv.fileStatsAPIHandler(rrAlice, reqAlice)
	if rrAlice.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for owner, got %d", rrAlice.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(rrAlice.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}
	if res["stats_enabled"] != true {
		t.Errorf("expected stats_enabled true, got %v", res["stats_enabled"])
	}
	if totalReads := res["total_reads"].(float64); totalReads != 3 {
		t.Errorf("expected total_reads 3, got %v", totalReads)
	}
	mobileMap := res["mobile"].(map[string]interface{})
	if mobileMap["count"].(float64) != 2 {
		t.Errorf("expected mobile count 2, got %v", mobileMap["count"])
	}
	if mobileMap["percentage"].(float64) < 66.6 {
		t.Errorf("expected mobile percentage ~66.7, got %v", mobileMap["percentage"])
	}
}

func TestRecoveryCodeAndPasswordReset(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
		JWTKey:    "test-jwt-secret",
		EnvOnly:   true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	srv := New(cfg, database)

	// Admin setup generates recovery code
	setupForm := strings.NewReader("storage_type=local&local_path=" + tempDir + "&username=admin&password=initialPass123")
	setupReq := httptest.NewRequest("POST", "/setup", setupForm)
	setupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	setupRR := httptest.NewRecorder()
	srv.setupHandler(setupRR, setupReq)
	if setupRR.Code != http.StatusFound {
		t.Fatalf("expected 302 after setup, got %d", setupRR.Code)
	}

	adminUser, err := db.GetUserByUsername(context.Background(), database, "admin")
	if err != nil || adminUser.RecoveryCodeHash == "" {
		t.Fatalf("expected admin recovery code hash to be set on setup")
	}
	adminCode, ok := srv.recoveryCodeStore.Load("admin")
	if !ok || adminCode == "" {
		t.Fatalf("expected admin plaintext recovery code in recoveryCodeStore after setup")
	}

	// Render dashboard once -> modal with recovery code shown, then cleared from store
	ctxAdmin := context.WithValue(context.Background(), "username", "admin")
	dashReq := httptest.NewRequest("GET", "/", nil).WithContext(ctxAdmin)
	dashRR := httptest.NewRecorder()
	srv.dashboardHandler(dashRR, dashReq)
	if !strings.Contains(dashRR.Body.String(), adminCode) {
		t.Errorf("expected dashboard to display newly generated admin recovery code %s", adminCode)
	}
	if _, stillThere := srv.recoveryCodeStore.Load("admin"); stillThere {
		t.Errorf("expected recoveryCodeStore to be cleared after rendering")
	}

	// Subuser creation and first login generates recovery code
	subHash, _ := bcrypt.GenerateFromPassword([]byte("subPass123"), bcrypt.DefaultCost)
	if err := db.CreateSubuser(context.Background(), database, "subuser1", string(subHash), 1024); err != nil {
		t.Fatalf("failed to create subuser: %v", err)
	}
	subBefore, _ := db.GetUserByUsername(context.Background(), database, "subuser1")
	if subBefore.RecoveryCodeHash != "" {
		t.Fatalf("expected subuser recovery code hash to be empty before first login")
	}

	loginForm := strings.NewReader("username=subuser1&password=subPass123")
	loginReq := httptest.NewRequest("POST", "/login", loginForm)
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	srv.loginHandler(loginRR, loginReq)
	if loginRR.Code != http.StatusFound {
		t.Fatalf("expected 302 on subuser login, got %d", loginRR.Code)
	}
	subAfter, _ := db.GetUserByUsername(context.Background(), database, "subuser1")
	if subAfter.RecoveryCodeHash == "" {
		t.Fatalf("expected subuser recovery code hash to be generated on first login")
	}
	if _, ok := srv.recoveryCodeStore.Load("subuser1"); !ok {
		t.Fatalf("expected subuser plaintext recovery code in store on first login")
	}

	// Regenerate recovery code in Account Security settings without re-authentication -> 403 Forbidden
	noAuthRegenReq := httptest.NewRequest("POST", "/settings/recovery/generate", nil).WithContext(ctxAdmin)
	noAuthRegenReq.Header.Set("Accept", "application/json")
	noAuthRegenRR := httptest.NewRecorder()
	srv.recoveryGenerateHandler(noAuthRegenRR, noAuthRegenReq)
	if noAuthRegenRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on recovery code regenerate without password/TOTP, got %d", noAuthRegenRR.Code)
	}

	// Regenerate recovery code with current password -> 200 OK
	regenReq := httptest.NewRequest("POST", "/settings/recovery/generate", strings.NewReader(`{"current_password":"initialPass123"}`)).WithContext(ctxAdmin)
	regenReq.Header.Set("Content-Type", "application/json")
	regenReq.Header.Set("Accept", "application/json")
	regenRR := httptest.NewRecorder()
	srv.recoveryGenerateHandler(regenRR, regenReq)
	if regenRR.Code != http.StatusOK {
		t.Fatalf("expected 200 on recovery code regenerate with password, got %d: %s", regenRR.Code, regenRR.Body.String())
	}
	var regenData map[string]string
	json.Unmarshal(regenRR.Body.Bytes(), &regenData)
	newAdminCode := regenData["recovery_code"]
	if newAdminCode == "" || newAdminCode == adminCode {
		t.Fatalf("expected a new distinct recovery code, got %q", newAdminCode)
	}

	// Password reset using recovery code rotates the code and stores the new one for display upon next login
	resetForm1 := strings.NewReader(fmt.Sprintf("username=admin&recovery_code=%s&new_password=resetPass1&confirm_password=resetPass1", newAdminCode))
	resetReq1 := httptest.NewRequest("POST", "/reset-password", resetForm1)
	resetReq1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resetRR1 := httptest.NewRecorder()
	srv.resetPasswordHandler(resetRR1, resetReq1)
	if resetRR1.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect after successful password reset, got %d", resetRR1.Code)
	}
	adminAfterReset1, _ := db.GetUserByUsername(context.Background(), database, "admin")
	if bcrypt.CompareHashAndPassword([]byte(adminAfterReset1.PasswordHash), []byte("resetPass1")) != nil {
		t.Errorf("expected password to be updated to resetPass1")
	}

	// Verify a fresh recovery code was generated and queued in recoveryCodeStore
	rotatedAdminCode, ok := srv.recoveryCodeStore.Load("admin")
	if !ok || rotatedAdminCode == "" || rotatedAdminCode == newAdminCode {
		t.Fatalf("expected a newly rotated recovery code in recoveryCodeStore after password reset")
	}

	// Reusing the old recovery code a second time MUST fail (one-time recovery code rotation)
	reuseForm := strings.NewReader(fmt.Sprintf("username=admin&recovery_code=%s&new_password=resetPassReuse&confirm_password=resetPassReuse", newAdminCode))
	reuseReq := httptest.NewRequest("POST", "/reset-password", reuseForm)
	reuseReq.RemoteAddr = "203.0.113.200:1234"
	reuseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuseRR := httptest.NewRecorder()
	srv.resetPasswordHandler(reuseRR, reuseReq)
	if reuseRR.Code == http.StatusFound {
		t.Fatalf("expected old recovery code to be rejected after single use, but reset succeeded!")
	}

	// Using the newly rotated recovery code succeeds
	resetForm2 := strings.NewReader(fmt.Sprintf("username=admin&recovery_code=%s&new_password=resetPass2&confirm_password=resetPass2", rotatedAdminCode))
	resetReq2 := httptest.NewRequest("POST", "/reset-password", resetForm2)
	resetReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resetRR2 := httptest.NewRecorder()
	srv.resetPasswordHandler(resetRR2, resetReq2)
	if resetRR2.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect on password reset with newly rotated recovery code, got %d", resetRR2.Code)
	}
	adminAfterReset2, _ := db.GetUserByUsername(context.Background(), database, "admin")
	if bcrypt.CompareHashAndPassword([]byte(adminAfterReset2.PasswordHash), []byte("resetPass2")) != nil {
		t.Errorf("expected password to be updated to resetPass2")
	}
	secondRotatedCode, _ := srv.recoveryCodeStore.Load("admin")

	// Rate limit: 3 failed attempts -> 1 hour block
	for i := 1; i <= 2; i++ {
		badForm := strings.NewReader("username=admin&recovery_code=XXXX-YYYY-ZZZZ-0000&new_password=a&confirm_password=a")
		badReq := httptest.NewRequest("POST", "/reset-password", badForm)
		badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		badRR := httptest.NewRecorder()
		srv.resetPasswordHandler(badRR, badReq)
		if badRR.Code != http.StatusOK {
			t.Fatalf("attempt %d: expected 200 with error message, got %d", i, badRR.Code)
		}
	}

	// 3rd failed attempt triggers the 1-hour block (429 Too Many Requests)
	badForm3 := strings.NewReader("username=nonexistent&recovery_code=XXXX-YYYY-ZZZZ-0000&new_password=a&confirm_password=a")
	badReq3 := httptest.NewRequest("POST", "/reset-password", badForm3)
	badReq3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badRR3 := httptest.NewRecorder()
	srv.resetPasswordHandler(badRR3, badReq3)
	if badRR3.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt 3: expected 429 TooManyRequests, got %d", badRR3.Code)
	}

	// Even a valid recovery code attempt must now be blocked while within the 1-hour window
	blockedValidForm := strings.NewReader(fmt.Sprintf("username=admin&recovery_code=%s&new_password=resetPass3&confirm_password=resetPass3", secondRotatedCode))
	blockedValidReq := httptest.NewRequest("POST", "/reset-password", blockedValidForm)
	blockedValidReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	blockedValidRR := httptest.NewRecorder()
	srv.resetPasswordHandler(blockedValidRR, blockedValidReq)
	if blockedValidRR.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 TooManyRequests when blocked, got %d", blockedValidRR.Code)
	}
}

func TestIndexingProtection(t *testing.T) {
	cfg := &config.Config{
		DBType:        "sqlite",
		SQLiteURL:     ":memory:",
		BlockIndexing: true,
		EnvOnly:       true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "admin", "hash"); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	srv := New(cfg, database)

	// 1. /robots.txt returns Disallow: / when BlockIndexing is true, even for Googlebot
	robotsReq := httptest.NewRequest("GET", "/robots.txt", nil)
	robotsReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	robotsRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(robotsRR, robotsReq)
	if robotsRR.Code != http.StatusOK {
		t.Fatalf("expected 200 on /robots.txt, got %d", robotsRR.Code)
	}
	if !strings.Contains(robotsRR.Body.String(), "Disallow: /") {
		t.Errorf("expected Disallow: / in /robots.txt, got %q", robotsRR.Body.String())
	}

	// 2. Search engine crawlers are blocked with 403 Forbidden
	crawlerUAs := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
		"Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)",
	}
	for _, ua := range crawlerUAs {
		req := httptest.NewRequest("GET", "/login", nil)
		req.Header.Set("User-Agent", ua)
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for crawler UA %q, got %d", ua, rr.Code)
		}
		if gotTag := rr.Header().Get("X-Robots-Tag"); !strings.Contains(gotTag, "noindex") {
			t.Errorf("expected X-Robots-Tag header with noindex, got %q", gotTag)
		}
	}

	// 3. Social preview bots (e.g. Discordbot, Twitterbot) and regular browsers are NOT blocked,
	//    and receive X-Robots-Tag header + <meta name="robots" ...> tags in HTML head.
	allowedUAs := []string{
		"Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
		"Twitterbot/1.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
	}
	for _, ua := range allowedUAs {
		req := httptest.NewRequest("GET", "/login", nil)
		req.Header.Set("User-Agent", ua)
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("expected 200 OK for allowed UA %q, got %d", ua, rr.Code)
		}
		if gotTag := rr.Header().Get("X-Robots-Tag"); !strings.Contains(gotTag, "noindex") {
			t.Errorf("expected X-Robots-Tag header with noindex, got %q", gotTag)
		}
		if !strings.Contains(rr.Body.String(), `<meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">`) {
			t.Errorf("expected robots meta tag in HTML head for UA %q", ua)
		}
	}

	// 4. Admin can toggle BlockIndexing off via /settings/action/indexing
	ctxAdmin := context.WithValue(context.Background(), "username", "admin")
	toggleForm := strings.NewReader("return_to=/settings/appearance") // block_indexing unchecked -> false
	toggleReq := httptest.NewRequest("POST", "/settings/action/indexing", toggleForm).WithContext(ctxAdmin)
	toggleReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	toggleRR := httptest.NewRecorder()
	srv.settingsActionHandler(toggleRR, toggleReq)
	if toggleRR.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect on indexing settings save, got %d", toggleRR.Code)
	}
	if srv.cfg.BlockIndexing {
		t.Errorf("expected BlockIndexing to be false after admin unchecked it")
	}

	// Verify Googlebot is now allowed and noindex meta tag is omitted when BlockIndexing is false
	gReq := httptest.NewRequest("GET", "/login", nil)
	gReq.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	gRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(gRR, gReq)
	if gRR.Code != http.StatusOK {
		t.Errorf("expected 200 OK for Googlebot when BlockIndexing is false, got %d", gRR.Code)
	}
	if strings.Contains(gRR.Body.String(), `<meta name="robots"`) {
		t.Errorf("did not expect robots noindex meta tag when BlockIndexing is false")
	}
}

func TestPersonalMediaEmbedPreview(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		BlockIndexing:    true,
		Accent:           "custom",
		CustomAccentHex:  "#5865f2",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	if err := db.CreateAdmin(context.Background(), database, "alice", "hash"); err != nil {
		t.Fatalf("failed to create alice: %v", err)
	}
	alice, _ := db.GetUserByUsername(context.Background(), database, "alice")

	srv := New(cfg, database)

	// Save a dummy PNG image and MP4 video
	pngBytes := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR")
	if err := srv.storage.Save(context.Background(), "shot.png", bytes.NewReader(pngBytes)); err != nil {
		t.Fatalf("failed to save image: %v", err)
	}
	if err := db.InsertFile(context.Background(), database, &db.File{
		UserID:       alice.ID,
		OriginalName: "screenshot.png",
		CustomName:   "Epic Screenshot",
		URLPath:      "shot",
		Size:         2048,
		StorageType:  "local",
		StoragePath:  "shot.png",
		StatsEnabled: true,
	}); err != nil {
		t.Fatalf("failed to insert file: %v", err)
	}
	shotFile, _ := db.GetFileByURL(context.Background(), database, "shot")

	// 1. Default user setting: Embed is DISABLED -> /f/shot serves raw image bytes directly
	req1 := httptest.NewRequest("GET", "/f/shot", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)")
	rr1 := httptest.NewRecorder()
	srv.serveFileHandler(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr1.Code)
	}
	if strings.Contains(rr1.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("expected raw image content-type when embed disabled, got %s", rr1.Header().Get("Content-Type"))
	}
	if !bytes.Equal(rr1.Body.Bytes(), pngBytes) {
		t.Errorf("expected raw PNG bytes when embed disabled")
	}

	// 2. Alice enables rich embed via personal settings POST /settings/action/embed
	ctxAlice := context.WithValue(context.Background(), "username", "alice")
	embedForm := strings.NewReader("embed_enabled=on&embed_color=%2300b0f4&embed_site_name=Alice+Clips&embed_custom_text=Captured+in+4K&embed_show_title=on&embed_show_size=on&embed_show_date=on&embed_show_author=on")
	embedReq := httptest.NewRequest("POST", "/settings/action/embed", embedForm).WithContext(ctxAlice)
	embedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	embedRR := httptest.NewRecorder()
	srv.settingsActionHandler(embedRR, embedReq)
	if embedRR.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect after saving embed settings, got %d", embedRR.Code)
	}

	// 3. Now /f/shot serves HTML embed page with OpenGraph / Twitter Card / oEmbed tags
	req2 := httptest.NewRequest("GET", "https://files.example.com/f/shot", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)")
	rr2 := httptest.NewRecorder()
	srv.serveFileHandler(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr2.Code)
	}
	if !strings.Contains(rr2.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("expected text/html for embed page, got %s", rr2.Header().Get("Content-Type"))
	}
	htmlBody := rr2.Body.String()
	expectedSnippets := []string{
		`<meta name="theme-color" content="#00b0f4">`,
		`<meta property="og:title" content="Epic Screenshot">`,
		`<meta property="og:site_name" content="Alice Clips">`,
		`<meta name="twitter:card" content="summary_large_image">`,
		`https://files.example.com/f/shot?raw=1`,
		`Captured in 4K`,
		`2.0 KB`,
		`@alice`,
	}
	for _, snippet := range expectedSnippets {
		if !strings.Contains(htmlBody, snippet) {
			t.Errorf("expected embed HTML to contain %q, got:\n%s", snippet, htmlBody)
		}
	}

	// 4. Requesting /f/shot?raw=1 returns the raw image bytes and does NOT double-count read stats
	time.Sleep(50 * time.Millisecond)
	statsBeforeRaw, _ := db.GetFileStats(context.Background(), database, shotFile.ID)

	reqRaw := httptest.NewRequest("GET", "https://files.example.com/f/shot?raw=1", nil)
	rrRaw := httptest.NewRecorder()
	srv.serveFileHandler(rrRaw, reqRaw)
	if rrRaw.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for ?raw=1, got %d", rrRaw.Code)
	}
	if !bytes.Equal(rrRaw.Body.Bytes(), pngBytes) {
		t.Errorf("expected raw PNG bytes on ?raw=1")
	}
	time.Sleep(50 * time.Millisecond)
	statsAfterRaw, _ := db.GetFileStats(context.Background(), database, shotFile.ID)
	if statsAfterRaw.TotalReads != statsBeforeRaw.TotalReads {
		t.Errorf("expected ?raw=1 sub-request not to increment read count (before=%d, after=%d)", statsBeforeRaw.TotalReads, statsAfterRaw.TotalReads)
	}

	// 5. /oembed?f=shot returns valid oEmbed JSON with Alice's personal settings
	oembedReq := httptest.NewRequest("GET", "https://files.example.com/oembed?f=shot", nil)
	oembedRR := httptest.NewRecorder()
	srv.oembedHandler(oembedRR, oembedReq)
	if oembedRR.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /oembed, got %d", oembedRR.Code)
	}
	var oembedData map[string]interface{}
	if err := json.Unmarshal(oembedRR.Body.Bytes(), &oembedData); err != nil {
		t.Fatalf("failed to unmarshal oEmbed JSON: %v", err)
	}
	if oembedData["provider_name"] != "Alice Clips" {
		t.Errorf("expected provider_name 'Alice Clips', got %v", oembedData["provider_name"])
	}
	if oembedData["author_name"] != "@alice" {
		t.Errorf("expected author_name '@alice', got %v", oembedData["author_name"])
	}
}

func TestSanitizeFileName(t *testing.T) {
	validCases := []struct {
		in   string
		want string
	}{
		{"report.pdf", "report.pdf"},
		{"../../etc/passwd", "passwd"},
		{"/../../../../app/data", "data"},
		{"..\\..\\config.json", "config.json"},
		{"C:\\Users\\alice\\notes.txt", "notes.txt"},
		{"hello\x00world\n.txt", "helloworld.txt"},
		{"   spaced.txt   ", "spaced.txt"},
	}
	for _, tc := range validCases {
		got, err := sanitizeFileName(tc.in)
		if err != nil {
			t.Errorf("sanitizeFileName(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("sanitizeFileName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	invalidCases := []string{
		"",
		"   ",
		".",
		"..",
		"/",
		"\\",
		"../..",
		"../../",
		"\x00\r\n\t",
		string([]byte{0xff, 0xfe, 0xfd}), // invalid UTF-8
		strings.Repeat("a", maxFileNameBytes+1),
	}
	for _, in := range invalidCases {
		if got, err := sanitizeFileName(in); err == nil {
			t.Errorf("sanitizeFileName(%q) expected error, got %q", in, got)
		}
	}
}

func FuzzSanitizeFileName(f *testing.F) {
	seeds := []string{
		"file.txt",
		"../x",
		"/../../x",
		"..\\x",
		"a/../../x",
		"file\x00name.txt",
		".",
		"..",
		"/",
		"\\",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, input string) {
		out, err := sanitizeFileName(input)
		if err != nil {
			return
		}
		if out == "" || out == "." || out == ".." || len(out) > maxFileNameBytes {
			t.Fatalf("sanitizeFileName(%q) returned invalid name %q", input, out)
		}
		if strings.ContainsAny(out, "/\\\x00\r\n") {
			t.Fatalf("sanitizeFileName(%q) returned name with forbidden characters: %q", input, out)
		}
	})
}

func TestChunkUploadPathTraversalPrevented(t *testing.T) {
	parentDir := t.TempDir()
	uploadsDir := filepath.Join(parentDir, "uploads")
	canaryDir := filepath.Join(parentDir, "data")
	if err := os.MkdirAll(canaryDir, 0o750); err != nil {
		t.Fatalf("failed to create canary dir: %v", err)
	}
	canaryFile := filepath.Join(canaryDir, "database.sqlite")
	if err := os.WriteFile(canaryFile, []byte("sqlite-db-canary"), 0o600); err != nil {
		t.Fatalf("failed to write canary file: %v", err)
	}
	canaryConfig := filepath.Join(parentDir, "config.json")
	if err := os.WriteFile(canaryConfig, []byte(`{"jwt_key":"safe"}`), 0o600); err != nil {
		t.Fatalf("failed to write canary config: %v", err)
	}

	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: uploadsDir,
		MaxUploadSizeMB:  10,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "attacker", "hash"); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	srv := New(cfg, database)
	ctx := context.WithValue(context.Background(), "username", "attacker")

	// 1. Pure traversal names with no valid base name are rejected with 400
	for _, badName := range []string{"", ".", "..", "../..", "/", "\\", "\x00"} {
		body, _ := json.Marshal(map[string]interface{}{
			"file_name":    badName,
			"total_size":   5,
			"total_chunks": 1,
		})
		req := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(body)).WithContext(ctx)
		rr := httptest.NewRecorder()
		srv.chunkUploadInitHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 BadRequest for file_name=%q, got %d", badName, rr.Code)
		}
	}

	// 2. Traversal payloads in file_name must never write outside chunkBaseDir or uploadsDir, and must never delete canaryDir.
	traversalPayloads := []struct {
		fileName string
		urlPath  string
		wantBase string
	}{
		{"/../../config.json", "poc-config", "config.json"},
		{"/../../../../" + canaryDir, "poc-data", "data"},
		{"..\\..\\config.json", "poc-win", "config.json"},
	}

	for _, tc := range traversalPayloads {
		initBody, _ := json.Marshal(map[string]interface{}{
			"file_name":    tc.fileName,
			"total_size":   12,
			"total_chunks": 1,
			"url_path":     tc.urlPath,
		})
		initReq := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(initBody)).WithContext(ctx)
		initRR := httptest.NewRecorder()
		srv.chunkUploadInitHandler(initRR, initReq)
		if initRR.Code != http.StatusOK {
			t.Fatalf("init(%q) expected 200, got %d: %s", tc.fileName, initRR.Code, initRR.Body.String())
		}
		var initRes map[string]string
		if err := json.Unmarshal(initRR.Body.Bytes(), &initRes); err != nil {
			t.Fatalf("failed to decode init response: %v", err)
		}
		uploadID := initRes["upload_id"]
		if !isValidUploadID(uploadID) || strings.Contains(uploadID, "config") || strings.Contains(uploadID, "..") {
			t.Fatalf("uploadID must be random and not contain user input, got %q", uploadID)
		}

		// Upload chunk 0
		var chunkBuf bytes.Buffer
		mw := multipart.NewWriter(&chunkBuf)
		_ = mw.WriteField("upload_id", uploadID)
		_ = mw.WriteField("chunk_index", "0")
		part, _ := mw.CreateFormFile("chunk", "chunk0")
		_, _ = part.Write([]byte("evil-content"))
		mw.Close()

		chunkReq := httptest.NewRequest("POST", "/api/upload/chunk", &chunkBuf).WithContext(ctx)
		chunkReq.Header.Set("Content-Type", mw.FormDataContentType())
		chunkRR := httptest.NewRecorder()
		srv.chunkUploadHandler(chunkRR, chunkReq)
		if chunkRR.Code != http.StatusOK {
			t.Fatalf("chunk upload failed: %d %s", chunkRR.Code, chunkRR.Body.String())
		}

		// Complete upload
		compBody, _ := json.Marshal(map[string]string{"upload_id": uploadID})
		compReq := httptest.NewRequest("POST", "/api/upload/complete", bytes.NewReader(compBody)).WithContext(ctx)
		compRR := httptest.NewRecorder()
		srv.chunkUploadCompleteHandler(compRR, compReq)
		if compRR.Code != http.StatusOK {
			t.Fatalf("complete upload failed: %d %s", compRR.Code, compRR.Body.String())
		}

		// Verify DB record has sanitized OriginalName and random StoragePath
		storedFile, err := db.GetFileByURL(context.Background(), database, tc.urlPath)
		if err != nil {
			t.Fatalf("GetFileByURL(%q) failed: %v", tc.urlPath, err)
		}
		if storedFile.OriginalName != tc.wantBase {
			t.Errorf("expected sanitized OriginalName %q, got %q", tc.wantBase, storedFile.OriginalName)
		}
		if strings.Contains(storedFile.StoragePath, "config") || strings.ContainsAny(storedFile.StoragePath, "/\\.") {
			t.Errorf("expected random StoragePath with no user filename or dots, got %q", storedFile.StoragePath)
		}
	}

	// Verify neither canaryFile nor canaryConfig was touched or deleted
	if got, err := os.ReadFile(canaryFile); err != nil || string(got) != "sqlite-db-canary" {
		t.Fatalf("canary database file was destroyed or altered: err=%v, content=%q", err, string(got))
	}
	if got, err := os.ReadFile(canaryConfig); err != nil || string(got) != `{"jwt_key":"safe"}` {
		t.Fatalf("canary config.json was overwritten or deleted: err=%v, content=%q", err, string(got))
	}
}

func TestWeakJWTKeyRejectedAndForgedTokenBlocked(t *testing.T) {
	weakKey := "weak-secret-key-too-short"
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
		JWTKey:    weakKey, // simulate invalid/weak key
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "admin", "hash"); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	// Server.New must replace the weak key with a strong random key
	srv := New(cfg, database)
	if srv.cfg.JWTKey == weakKey || !config.IsValidJWTKey(srv.cfg.JWTKey) {
		t.Fatalf("expected Server.New to replace weak key with a strong random key, got %q", srv.cfg.JWTKey)
	}

	// Attacker forges an admin token using the weak key
	forgedToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": "admin",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	forgedStr, err := forgedToken.SignedString([]byte(weakKey))
	if err != nil {
		t.Fatalf("failed to sign forged token: %v", err)
	}

	req := httptest.NewRequest("GET", "/settings", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: forgedStr})
	rr := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
		t.Fatalf("expected forged token signed with weak key to be rejected with 302 -> /login, got %d (Location=%q)", rr.Code, rr.Header().Get("Location"))
	}

	// Even if someone mutates srv.cfg.JWTKey back to the weak key at runtime, parseJWTUsername refuses it
	srv.mu.Lock()
	srv.cfg.JWTKey = weakKey
	srv.mu.Unlock()
	if _, ok := srv.parseJWTUsername(forgedStr); ok {
		t.Fatalf("parseJWTUsername must never accept tokens when JWTKey is invalid")
	}
}

func TestStoredXSSMitigatedOnServedFiles(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "admin", "hash"); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	srv := New(cfg, database)

	// Upload active/sniffable payloads: HTML, SVG with script, and extensionless HTML content
	testFiles := []struct {
		key          string
		originalName string
		customName   string
		urlPath      string
		payload      string
		wantMime     string
		wantDisp     string
	}{
		{
			key:          "xsshtml",
			originalName: "exploit.html",
			customName:   `evil"; injected=1`,
			urlPath:      "xss-html",
			payload:      `<!DOCTYPE html><script>fetch('/settings/users/add')</script>`,
			wantMime:     "application/octet-stream",
			wantDisp:     "attachment",
		},
		{
			key:          "xsssvg",
			originalName: "image.svg",
			urlPath:      "xss-svg",
			payload:      `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>`,
			wantMime:     "application/octet-stream",
			wantDisp:     "attachment",
		},
		{
			key:          "sniffed",
			originalName: "README",
			urlPath:      "xss-sniff",
			payload:      `<html><body><script>alert(1)</script></body></html>`,
			wantMime:     "application/octet-stream",
			wantDisp:     "attachment",
		},
		{
			key:          "safeimg",
			originalName: "photo.png",
			urlPath:      "safe-png",
			payload:      "\x89PNG\r\n\x1a\n",
			wantMime:     "image/png",
			wantDisp:     "inline",
		},
		{
			key:          "safepdf",
			originalName: "doc.pdf",
			urlPath:      "safe-pdf",
			payload:      "%PDF-1.7",
			wantMime:     "application/pdf",
			wantDisp:     "inline",
		},
	}

	for _, tf := range testFiles {
		if err := srv.storage.Save(context.Background(), tf.key, strings.NewReader(tf.payload)); err != nil {
			t.Fatalf("failed to save %s: %v", tf.key, err)
		}
		if err := db.InsertFile(context.Background(), database, &db.File{
			OriginalName: tf.originalName,
			CustomName:   tf.customName,
			URLPath:      tf.urlPath,
			Size:         int64(len(tf.payload)),
			StorageType:  "local",
			StoragePath:  tf.key,
			UserID:       1,
		}); err != nil {
			t.Fatalf("failed to insert %s: %v", tf.key, err)
		}

		req := httptest.NewRequest("GET", "/f/"+tf.urlPath+"?raw=1", nil)
		rr := httptest.NewRecorder()
		srv.serveFileHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("GET /f/%s status = %d, want 200", tf.urlPath, rr.Code)
		}
		h := rr.Header()
		if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
			t.Errorf("%s: X-Content-Type-Options = %q, want 'nosniff'", tf.urlPath, got)
		}
		csp := h.Get("Content-Security-Policy")
		if !strings.HasPrefix(csp, "sandbox;") || strings.Contains(csp, "allow-scripts") || strings.Contains(csp, "allow-same-origin") {
			t.Errorf("%s: unexpected CSP %q (must start with 'sandbox;' and not allow scripts/same-origin)", tf.urlPath, csp)
		}
		if got := h.Get("Cross-Origin-Resource-Policy"); got != "same-site" {
			t.Errorf("%s: Cross-Origin-Resource-Policy = %q, want 'same-site'", tf.urlPath, got)
		}
		if got := h.Get("Content-Type"); got != tf.wantMime {
			t.Errorf("%s: Content-Type = %q, want %q", tf.urlPath, got, tf.wantMime)
		}
		cd := h.Get("Content-Disposition")
		if !strings.HasPrefix(cd, tf.wantDisp+";") {
			t.Errorf("%s: Content-Disposition = %q, expected prefix %q", tf.urlPath, cd, tf.wantDisp+";")
		}
		// Ensure quote injection in custom_name is properly escaped by mime.FormatMediaType
		if tf.customName != "" && strings.Contains(cd, `filename="evil"; injected=1"`) {
			t.Errorf("%s: Content-Disposition vulnerable to quote injection: %q", tf.urlPath, cd)
		}
	}
}

func TestSetupFailClosedTokenAndLockout(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		EnvOnly:          true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	srv := New(cfg, database)
	token := srv.EnableSetupToken()
	if token == "" {
		t.Fatalf("expected non-empty setup token")
	}

	// 1. POST /setup without token or with wrong token is rejected with 403 Forbidden
	noTokenForm := strings.NewReader("storage_type=local&local_path=" + tempDir + "&username=evil&password=Password123!")
	noTokenReq := httptest.NewRequest("POST", "/setup", noTokenForm)
	noTokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	noTokenRR := httptest.NewRecorder()
	srv.setupHandler(noTokenRR, noTokenReq)
	if noTokenRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when setup_token is missing, got %d", noTokenRR.Code)
	}

	// 2. POST /setup with valid token but dangerous local_path (e.g. "/" or "../outside") is rejected
	for _, badPath := range []string{"/", "../escape", "/../../etc"} {
		badForm := strings.NewReader("setup_token=" + token + "&storage_type=local&local_path=" + badPath + "&username=admin&password=Password123!")
		badReq := httptest.NewRequest("POST", "/setup", badForm)
		badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		badRR := httptest.NewRecorder()
		srv.setupHandler(badRR, badReq)
		if badRR.Code == http.StatusFound {
			t.Fatalf("expected setup with dangerous local_path %q to be rejected, got 302 redirect", badPath)
		}
	}

	// 3. Valid setup with token succeeds and locks setup permanently
	validForm := strings.NewReader("setup_token=" + token + "&storage_type=local&local_path=" + tempDir + "&username=admin&password=Password123!")
	validReq := httptest.NewRequest("POST", "/setup", validForm)
	validReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	validRR := httptest.NewRecorder()
	srv.setupHandler(validRR, validReq)
	if validRR.Code != http.StatusFound || validRR.Header().Get("Location") != "/" {
		t.Fatalf("expected 302 -> / on valid setup, got %d (Location=%q)", validRR.Code, validRR.Header().Get("Location"))
	}

	// 4. Subsequent POST /setup (even with the token) is redirected to "/" and does not create a second admin
	secondForm := strings.NewReader("setup_token=" + token + "&storage_type=local&local_path=" + tempDir + "&username=attacker&password=Password123!")
	secondReq := httptest.NewRequest("POST", "/setup", secondForm)
	secondReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	secondRR := httptest.NewRecorder()
	srv.setupHandler(secondRR, secondReq)
	if secondRR.Code != http.StatusFound || secondRR.Header().Get("Location") != "/" {
		t.Fatalf("expected 302 -> / when already configured, got %d", secondRR.Code)
	}
	if _, err := db.GetUserByUsername(context.Background(), database, "attacker"); err == nil {
		t.Fatalf("attacker admin should not have been created after setup completed")
	}

	// 5. Direct db.CreateAdmin call when an admin already exists fails with db.ErrAdminAlreadyExists
	if err := db.CreateAdmin(context.Background(), database, "secondadmin", "hash"); !errors.Is(err, db.ErrAdminAlreadyExists) {
		t.Fatalf("expected ErrAdminAlreadyExists on second CreateAdmin, got %v", err)
	}

	// 6. Simulate a database outage on a non-cached server: CheckConfigured returns error, and handlers return 503 Service Unavailable instead of redirecting to /setup!
	closedDB, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init second db: %v", err)
	}
	closedDB.Close() // force DB error on HasAdmin

	srvBroken := New(cfg, closedDB)
	loginReq := httptest.NewRequest("GET", "/login", nil)
	loginRR := httptest.NewRecorder()
	srvBroken.loginHandler(loginRR, loginReq)
	if loginRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable on /login when DB fails, got %d (Location=%q)", loginRR.Code, loginRR.Header().Get("Location"))
	}

	setupReq := httptest.NewRequest("GET", "/setup", nil)
	setupRR := httptest.NewRecorder()
	srvBroken.setupHandler(setupRR, setupReq)
	if setupRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable on /setup when DB fails, got %d", setupRR.Code)
	}
}

func TestLoginAnd2FABruteForceAndReplayProtection(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	passHash, _ := bcrypt.GenerateFromPassword([]byte("CorrectPassword123!"), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(passHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}
	_, recHash, _ := generateRecoveryCode()
	_ = db.UpdateRecoveryCode(context.Background(), database, "admin", recHash)

	srv := New(cfg, database)

	// 1. /login brute-force rate limit: 10 failed attempts from an attacker IP trigger 429 + Retry-After
	for i := 1; i <= loginMaxAttempts; i++ {
		form := strings.NewReader("username=admin&password=WrongPassword")
		req := httptest.NewRequest("POST", "/login", form)
		req.RemoteAddr = "198.51.100.42:54321"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.loginHandler(rr, req)

		if i < loginMaxAttempts {
			if rr.Code != http.StatusOK {
				t.Fatalf("attempt %d: expected 200 OK with error form, got %d", i, rr.Code)
			}
		} else {
			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("attempt %d: expected 429 TooManyRequests, got %d", i, rr.Code)
			}
			if rr.Header().Get("Retry-After") == "" {
				t.Errorf("expected Retry-After header on 429 response")
			}
		}
	}

	// Legitimate user on a different IP is NOT locked out by the attacker's IP
	legitForm := strings.NewReader("username=admin&password=CorrectPassword123!")
	legitReq := httptest.NewRequest("POST", "/login", legitForm)
	legitReq.RemoteAddr = "203.0.113.7:12345"
	legitReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	legitRR := httptest.NewRecorder()
	srv.loginHandler(legitRR, legitReq)
	if legitRR.Code != http.StatusFound || legitRR.Header().Get("Location") != "/" {
		t.Fatalf("expected legitimate user on another IP to succeed with 302 -> /, got %d", legitRR.Code)
	}

	// 2. /reset-password per-IP isolation: attacker IP hitting 429 does not lock out legitimate IP
	for i := 1; i <= resetMaxAttempts; i++ {
		form := strings.NewReader("username=admin&recovery_code=XXXX-XXXX-XXXX-XXXX&new_password=New1!&confirm_password=New1!")
		req := httptest.NewRequest("POST", "/reset-password", form)
		req.RemoteAddr = "198.51.100.99:11111"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.resetPasswordHandler(rr, req)
		if i == resetMaxAttempts && rr.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 on %dth reset failure, got %d", i, rr.Code)
		}
	}
	otherIPForm := strings.NewReader("username=admin&recovery_code=YYYY-YYYY-YYYY-YYYY&new_password=New1!&confirm_password=New1!")
	otherIPReq := httptest.NewRequest("POST", "/reset-password", otherIPForm)
	otherIPReq.RemoteAddr = "203.0.113.88:22222"
	otherIPReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	otherIPRR := httptest.NewRecorder()
	srv.resetPasswordHandler(otherIPRR, otherIPReq)
	if otherIPRR.Code == http.StatusTooManyRequests {
		t.Fatalf("attacker IP lockout on /reset-password must not lock out a different client IP")
	}

	// 3. /login/2fa session attempt cap (max 5 failed attempts invalidates the 2fa_session)
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "FileLine",
		AccountName: "admin",
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP key: %v", err)
	}
	if err := db.UpdateUserAuthData(context.Background(), database, "admin", key.Secret(), "[]"); err != nil {
		t.Fatalf("failed to set TOTP secret: %v", err)
	}

	// Login to get a fresh 2fa_session cookie
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader("username=admin&password=CorrectPassword123!"))
	loginReq.RemoteAddr = "203.0.113.50:4000"
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	srv.loginHandler(loginRR, loginReq)
	if loginRR.Code != http.StatusFound || loginRR.Header().Get("Location") != "/login/2fa" {
		t.Fatalf("expected redirect to /login/2fa, got %d (%s)", loginRR.Code, loginRR.Header().Get("Location"))
	}
	var twoFACookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "2fa_session" {
			twoFACookie = c
			break
		}
	}
	if twoFACookie == nil {
		t.Fatalf("expected 2fa_session cookie")
	}

	// Submit 5 wrong 6-digit codes; on the 5th attempt the session must be deleted and redirect to /login
	for i := 1; i <= twoFAMaxAttempts; i++ {
		req := httptest.NewRequest("POST", "/login/2fa", strings.NewReader("code=000000"))
		req.RemoteAddr = "203.0.113.50:4000"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(twoFACookie)
		rr := httptest.NewRecorder()
		srv.login2FAHandler(rr, req)

		if i < twoFAMaxAttempts {
			if rr.Code != http.StatusOK {
				t.Fatalf("2FA failure %d: expected 200 error page, got %d", i, rr.Code)
			}
		} else {
			if rr.Code != http.StatusFound || !strings.HasPrefix(rr.Header().Get("Location"), "/login") {
				t.Fatalf("5th 2FA failure must invalidate session and redirect to /login, got %d (%s)", rr.Code, rr.Header().Get("Location"))
			}
		}
	}

	// 4. TOTP replay protection: a valid 6-digit code can only be used once within its time-step
	loginReq2 := httptest.NewRequest("POST", "/login", strings.NewReader("username=admin&password=CorrectPassword123!"))
	loginReq2.RemoteAddr = "203.0.113.51:4000"
	loginReq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR2 := httptest.NewRecorder()
	srv.loginHandler(loginRR2, loginReq2)
	var cookie1 *http.Cookie
	for _, c := range loginRR2.Result().Cookies() {
		if c.Name == "2fa_session" {
			cookie1 = c
		}
	}

	loginReq3 := httptest.NewRequest("POST", "/login", strings.NewReader("username=admin&password=CorrectPassword123!"))
	loginReq3.RemoteAddr = "203.0.113.52:4000"
	loginReq3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR3 := httptest.NewRecorder()
	srv.loginHandler(loginRR3, loginReq3)
	var cookie2 *http.Cookie
	for _, c := range loginRR3.Result().Cookies() {
		if c.Name == "2fa_session" {
			cookie2 = c
		}
	}

	validCode, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}

	// First use of validCode succeeds
	use1Req := httptest.NewRequest("POST", "/login/2fa", strings.NewReader("code="+validCode))
	use1Req.RemoteAddr = "203.0.113.51:4000"
	use1Req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	use1Req.AddCookie(cookie1)
	use1RR := httptest.NewRecorder()
	srv.login2FAHandler(use1RR, use1Req)
	if use1RR.Code != http.StatusFound || use1RR.Header().Get("Location") != "/" {
		t.Fatalf("expected first use of TOTP code to succeed, got %d (%s)", use1RR.Code, use1RR.Header().Get("Location"))
	}

	// Second use (replay) of the exact same validCode in the same 30s window is rejected
	use2Req := httptest.NewRequest("POST", "/login/2fa", strings.NewReader("code="+validCode))
	use2Req.RemoteAddr = "203.0.113.52:4000"
	use2Req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	use2Req.AddCookie(cookie2)
	use2RR := httptest.NewRecorder()
	srv.login2FAHandler(use2RR, use2Req)
	if use2RR.Code == http.StatusFound && use2RR.Header().Get("Location") == "/" {
		t.Fatalf("replayed TOTP code within the same 30s window must be rejected, but succeeded!")
	}
}

func TestChunkUploadBoundsAndQuotaEnforcement(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        filepath.Join(tempDir, "test.db"),
		StorageType:      "local",
		LocalStoragePath: tempDir,
		MaxUploadSizeMB:  1, // 1 MB max upload size
		ChunkSizeMB:      1, // 1 MB chunk size
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "uploader", "hash"); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	srv := New(cfg, database)
	ctx := context.WithValue(context.Background(), "username", "uploader")

	// 1. Negative, zero, or huge TotalChunks / TotalSize values are rejected with 400 (no panic or OOM)
	badInits := []map[string]interface{}{
		{"file_name": "a.bin", "total_size": 100, "total_chunks": -1},
		{"file_name": "a.bin", "total_size": 100, "total_chunks": 0},
		{"file_name": "a.bin", "total_size": 100, "total_chunks": 2147483647},
		{"file_name": "a.bin", "total_size": 0, "total_chunks": 1},
		{"file_name": "a.bin", "total_size": -50, "total_chunks": 1},
		// Mismatched total_chunks vs total_size (100 bytes with 1MB chunks expects 1 chunk, not 50)
		{"file_name": "a.bin", "total_size": 100, "total_chunks": 50},
	}
	for _, payload := range badInits {
		b, _ := json.Marshal(payload)
		req := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(b)).WithContext(ctx)
		rr := httptest.NewRecorder()
		srv.chunkUploadInitHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 BadRequest for payload %v, got %d", payload, rr.Code)
		}
	}

	// 2. Declare TotalSize = 10 bytes, TotalChunks = 1, but upload 20 bytes -> rejected!
	initBody, _ := json.Marshal(map[string]interface{}{
		"file_name":    "mismatch.bin",
		"total_size":   10,
		"total_chunks": 1,
	})
	initReq := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(initBody)).WithContext(ctx)
	initRR := httptest.NewRecorder()
	srv.chunkUploadInitHandler(initRR, initReq)
	if initRR.Code != http.StatusOK {
		t.Fatalf("init expected 200, got %d: %s", initRR.Code, initRR.Body.String())
	}
	var initRes map[string]string
	_ = json.Unmarshal(initRR.Body.Bytes(), &initRes)
	uploadID := initRes["upload_id"]

	// Uploading 20 bytes when TotalSize is 10 bytes must be rejected by chunkUploadHandler
	var overBuf bytes.Buffer
	mw := multipart.NewWriter(&overBuf)
	_ = mw.WriteField("upload_id", uploadID)
	_ = mw.WriteField("chunk_index", "0")
	part, _ := mw.CreateFormFile("chunk", "chunk0")
	_, _ = part.Write([]byte("01234567890123456789")) // 20 bytes > 10 bytes TotalSize
	mw.Close()

	overReq := httptest.NewRequest("POST", "/api/upload/chunk", &overBuf).WithContext(ctx)
	overReq.Header.Set("Content-Type", mw.FormDataContentType())
	overRR := httptest.NewRecorder()
	srv.chunkUploadHandler(overRR, overReq)
	if overRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when chunk bytes exceed declared TotalSize, got %d", overRR.Code)
	}

	// Now upload only 5 bytes (< 10 bytes declared) and try to complete -> rejected because actualSize (5) != TotalSize (10)
	var shortBuf bytes.Buffer
	mwShort := multipart.NewWriter(&shortBuf)
	_ = mwShort.WriteField("upload_id", uploadID)
	_ = mwShort.WriteField("chunk_index", "0")
	partShort, _ := mwShort.CreateFormFile("chunk", "chunk0")
	_, _ = partShort.Write([]byte("01234")) // 5 bytes
	mwShort.Close()

	shortReq := httptest.NewRequest("POST", "/api/upload/chunk", &shortBuf).WithContext(ctx)
	shortReq.Header.Set("Content-Type", mwShort.FormDataContentType())
	shortRR := httptest.NewRecorder()
	srv.chunkUploadHandler(shortRR, shortReq)
	if shortRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for 5-byte chunk, got %d: %s", shortRR.Code, shortRR.Body.String())
	}

	compBody, _ := json.Marshal(map[string]string{"upload_id": uploadID})
	compReq := httptest.NewRequest("POST", "/api/upload/complete", bytes.NewReader(compBody)).WithContext(ctx)
	compRR := httptest.NewRecorder()
	srv.chunkUploadCompleteHandler(compRR, compReq)
	if compRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when assembled size (5) != declared TotalSize (10), got %d", compRR.Code)
	}

	// 3. Concurrent /api/upload/complete calls for the same session: exactly one succeeds
	initBody2, _ := json.Marshal(map[string]interface{}{
		"file_name":    "race.bin",
		"total_size":   10,
		"total_chunks": 1,
		"url_path":     "race-file",
	})
	initReq2 := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(initBody2)).WithContext(ctx)
	initRR2 := httptest.NewRecorder()
	srv.chunkUploadInitHandler(initRR2, initReq2)
	var initRes2 map[string]string
	_ = json.Unmarshal(initRR2.Body.Bytes(), &initRes2)
	raceUploadID := initRes2["upload_id"]

	var validBuf bytes.Buffer
	mwValid := multipart.NewWriter(&validBuf)
	_ = mwValid.WriteField("upload_id", raceUploadID)
	_ = mwValid.WriteField("chunk_index", "0")
	partValid, _ := mwValid.CreateFormFile("chunk", "chunk0")
	_, _ = partValid.Write([]byte("0123456789"))
	mwValid.Close()

	validChunkReq := httptest.NewRequest("POST", "/api/upload/chunk", &validBuf).WithContext(ctx)
	validChunkReq.Header.Set("Content-Type", mwValid.FormDataContentType())
	validChunkRR := httptest.NewRecorder()
	srv.chunkUploadHandler(validChunkRR, validChunkReq)
	if validChunkRR.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid chunk, got %d", validChunkRR.Code)
	}

	var wg sync.WaitGroup
	codes := make([]int, 2)
	for idx := 0; idx < 2; idx++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cb, _ := json.Marshal(map[string]string{"upload_id": raceUploadID})
			creq := httptest.NewRequest("POST", "/api/upload/complete", bytes.NewReader(cb)).WithContext(ctx)
			crr := httptest.NewRecorder()
			srv.chunkUploadCompleteHandler(crr, creq)
			codes[i] = crr.Code
		}(idx)
	}
	wg.Wait()

	successCount := 0
	for _, c := range codes {
		if c == http.StatusOK {
			successCount++
		}
	}
	if successCount != 1 {
		t.Fatalf("expected exactly 1 concurrent complete call to succeed (200 OK), got codes=%v", codes)
	}

	// 4. Expired upload sessions are cleaned up by cleanupExpiredUploads
	initBody3, _ := json.Marshal(map[string]interface{}{
		"file_name":    "abandoned.bin",
		"total_size":   10,
		"total_chunks": 1,
	})
	initReq3 := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(initBody3)).WithContext(ctx)
	initRR3 := httptest.NewRecorder()
	srv.chunkUploadInitHandler(initRR3, initReq3)
	var initRes3 map[string]string
	_ = json.Unmarshal(initRR3.Body.Bytes(), &initRes3)
	abandonedID := initRes3["upload_id"]

	srv.cleanupExpiredUploads(time.Now().Add(chunkUploadTTL + time.Minute))
	srv.chunkMu.RLock()
	_, stillExists := srv.chunkUploads[abandonedID]
	srv.chunkMu.RUnlock()
	if stillExists {
		t.Fatalf("expected expired upload session %q to be removed by janitor", abandonedID)
	}
}

func TestChunkUploadSessionOwnerBinding(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		MaxUploadSizeMB:  10,
		ChunkSizeMB:      1,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "alice", "hash"); err != nil {
		t.Fatalf("failed to create alice: %v", err)
	}
	if err := db.CreateSubuser(context.Background(), database, "bob", "hash", 10); err != nil {
		t.Fatalf("failed to create bob: %v", err)
	}

	srv := New(cfg, database)
	ctxAlice := context.WithValue(context.Background(), "username", "alice")
	ctxBob := context.WithValue(context.Background(), "username", "bob")

	// Alice initiates a chunked upload
	initBody, _ := json.Marshal(map[string]interface{}{
		"file_name":    "alice-report.txt",
		"total_size":   12,
		"total_chunks": 1,
		"url_path":     "alice-report",
	})
	initReq := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(initBody)).WithContext(ctxAlice)
	initRR := httptest.NewRecorder()
	srv.chunkUploadInitHandler(initRR, initReq)
	if initRR.Code != http.StatusOK {
		t.Fatalf("alice init failed: %d %s", initRR.Code, initRR.Body.String())
	}
	var initRes map[string]string
	_ = json.Unmarshal(initRR.Body.Bytes(), &initRes)
	uploadID := initRes["upload_id"]

	// 1. Bob tries to upload a chunk to Alice's upload_id -> must get 404 Not Found
	var bobChunkBuf bytes.Buffer
	mwBob := multipart.NewWriter(&bobChunkBuf)
	_ = mwBob.WriteField("upload_id", uploadID)
	_ = mwBob.WriteField("chunk_index", "0")
	partBob, _ := mwBob.CreateFormFile("chunk", "chunk0")
	_, _ = partBob.Write([]byte("bob-injected"))
	mwBob.Close()

	bobChunkReq := httptest.NewRequest("POST", "/api/upload/chunk", &bobChunkBuf).WithContext(ctxBob)
	bobChunkReq.Header.Set("Content-Type", mwBob.FormDataContentType())
	bobChunkRR := httptest.NewRecorder()
	srv.chunkUploadHandler(bobChunkRR, bobChunkReq)
	if bobChunkRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 NotFound when bob attempts to upload chunk to alice's session, got %d", bobChunkRR.Code)
	}

	// 2. Bob tries to complete Alice's upload session early -> must get 404 Not Found (and must NOT delete Alice's session)
	bobCompBody, _ := json.Marshal(map[string]string{"upload_id": uploadID})
	bobCompReq := httptest.NewRequest("POST", "/api/upload/complete", bytes.NewReader(bobCompBody)).WithContext(ctxBob)
	bobCompRR := httptest.NewRecorder()
	srv.chunkUploadCompleteHandler(bobCompRR, bobCompReq)
	if bobCompRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 NotFound when bob attempts to complete alice's session, got %d", bobCompRR.Code)
	}

	// 3. Alice uploads her own chunk and completes the upload -> succeeds with Alice's content intact
	var aliceChunkBuf bytes.Buffer
	mwAlice := multipart.NewWriter(&aliceChunkBuf)
	_ = mwAlice.WriteField("upload_id", uploadID)
	_ = mwAlice.WriteField("chunk_index", "0")
	partAlice, _ := mwAlice.CreateFormFile("chunk", "chunk0")
	_, _ = partAlice.Write([]byte("alice-secret"))
	mwAlice.Close()

	aliceChunkReq := httptest.NewRequest("POST", "/api/upload/chunk", &aliceChunkBuf).WithContext(ctxAlice)
	aliceChunkReq.Header.Set("Content-Type", mwAlice.FormDataContentType())
	aliceChunkRR := httptest.NewRecorder()
	srv.chunkUploadHandler(aliceChunkRR, aliceChunkReq)
	if aliceChunkRR.Code != http.StatusOK {
		t.Fatalf("alice chunk upload failed: %d %s", aliceChunkRR.Code, aliceChunkRR.Body.String())
	}

	// Bob tries to complete Alice's session AFTER Alice uploaded her chunk -> still 404 Not Found
	bobCompReq2 := httptest.NewRequest("POST", "/api/upload/complete", bytes.NewReader(bobCompBody)).WithContext(ctxBob)
	bobCompRR2 := httptest.NewRecorder()
	srv.chunkUploadCompleteHandler(bobCompRR2, bobCompReq2)
	if bobCompRR2.Code != http.StatusNotFound {
		t.Fatalf("expected 404 NotFound when bob attempts to complete alice's ready session, got %d", bobCompRR2.Code)
	}

	// Alice completes her upload -> 200 OK
	aliceCompReq := httptest.NewRequest("POST", "/api/upload/complete", bytes.NewReader(bobCompBody)).WithContext(ctxAlice)
	aliceCompRR := httptest.NewRecorder()
	srv.chunkUploadCompleteHandler(aliceCompRR, aliceCompReq)
	if aliceCompRR.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when alice completes her own session, got %d: %s", aliceCompRR.Code, aliceCompRR.Body.String())
	}

	stored, err := db.GetFileByURL(context.Background(), database, "alice-report")
	if err != nil {
		t.Fatalf("failed to load alice-report: %v", err)
	}
	rc, err := srv.storage.Get(context.Background(), stored.StoragePath)
	if err != nil {
		t.Fatalf("failed to read stored file: %v", err)
	}
	defer rc.Close()
	var got bytes.Buffer
	_, _ = got.ReadFrom(rc)
	if got.String() != "alice-secret" {
		t.Fatalf("expected 'alice-secret', got %q", got.String())
	}
}

func TestRequestBodySizeLimitsAndLogoValidation(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		MaxUploadSizeMB:  1, // 1 MB max upload
		EnvOnly:          true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "admin", "hash"); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	srv := New(cfg, database)
	ctxAdmin := context.WithValue(context.Background(), "username", "admin")

	// 1. Oversized form/JSON bodies (> 64 KB) on auth/settings endpoints are rejected with 413 RequestEntityTooLarge
	bigForm := "username=admin&password=" + strings.Repeat("A", 100*1024)
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader(bigForm))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	srv.loginHandler(loginRR, loginReq)
	if loginRR.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 RequestEntityTooLarge on oversized /login body, got %d", loginRR.Code)
	}

	bigJSON := `{"file_name":"a.txt","total_size":10,"total_chunks":1,"custom_name":"` + strings.Repeat("B", 100*1024) + `"}`
	initReq := httptest.NewRequest("POST", "/api/upload/init", strings.NewReader(bigJSON)).WithContext(ctxAdmin)
	initRR := httptest.NewRecorder()
	srv.chunkUploadInitHandler(initRR, initReq)
	if initRR.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 RequestEntityTooLarge on oversized /api/upload/init body, got %d", initRR.Code)
	}

	// 2. Oversized multipart file upload (> MaxUploadSizeMB + 1MB overhead) is rejected with 413 before spooling unbounded data
	var bigUploadBuf bytes.Buffer
	mwUp := multipart.NewWriter(&bigUploadBuf)
	partUp, _ := mwUp.CreateFormFile("file", "huge.bin")
	_, _ = partUp.Write(bytes.Repeat([]byte("X"), (2<<20)+4096)) // > 2 MB (MaxUploadSizeMB=1 + 1MB overhead)
	mwUp.Close()

	upReq := httptest.NewRequest("POST", "/upload", &bigUploadBuf).WithContext(ctxAdmin)
	upReq.Header.Set("Content-Type", mwUp.FormDataContentType())
	upRR := httptest.NewRecorder()
	srv.uploadHandler(upRR, upReq)
	if upRR.Code != http.StatusRequestEntityTooLarge && upRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 413 or 400 on oversized /upload body, got %d", upRR.Code)
	}

	// 3. Logo upload > 1 MB is rejected with 413
	var bigLogoBuf bytes.Buffer
	mwLogo := multipart.NewWriter(&bigLogoBuf)
	partLogo, _ := mwLogo.CreateFormFile("custom_logo_file", "logo.png")
	_, _ = partLogo.Write([]byte("\x89PNG\r\n\x1a\n"))
	_, _ = partLogo.Write(bytes.Repeat([]byte("P"), (1<<20)+128*1024))
	mwLogo.Close()

	bigLogoReq := httptest.NewRequest("POST", "/settings/action/appearance", &bigLogoBuf).WithContext(ctxAdmin)
	bigLogoReq.Header.Set("Content-Type", mwLogo.FormDataContentType())
	bigLogoRR := httptest.NewRecorder()
	srv.settingsActionHandler(bigLogoRR, bigLogoReq)
	if bigLogoRR.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 RequestEntityTooLarge on >1MB logo upload, got %d", bigLogoRR.Code)
	}

	// 4. Logo upload with .png extension but non-PNG magic bytes (e.g. HTML/text) is rejected
	var fakePngBuf bytes.Buffer
	mwFake := multipart.NewWriter(&fakePngBuf)
	partFake, _ := mwFake.CreateFormFile("custom_logo_file", "fake.png")
	_, _ = partFake.Write([]byte("<html><script>alert(1)</script></html>"))
	mwFake.Close()

	fakePngReq := httptest.NewRequest("POST", "/settings/action/appearance", &fakePngBuf).WithContext(ctxAdmin)
	fakePngReq.Header.Set("Content-Type", mwFake.FormDataContentType())
	fakePngRR := httptest.NewRecorder()
	srv.settingsActionHandler(fakePngRR, fakePngReq)
	if !strings.Contains(fakePngRR.Header().Get("Location"), "error=") {
		t.Fatalf("expected redirect with error when uploading .png with invalid magic bytes, got Location=%q", fakePngRR.Header().Get("Location"))
	}
}

func extractSessionCookie(rr *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rr.Result().Cookies() {
		if c.Name == "session" && c.Value != "" && c.MaxAge >= 0 {
			return c
		}
	}
	return nil
}

func TestSessionRevocation(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
		EnvOnly:   true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	adminPassHash, _ := bcrypt.GenerateFromPassword([]byte("AdminPass123!"), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(adminPassHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}
	subPassHash, _ := bcrypt.GenerateFromPassword([]byte("SubPass123!"), bcrypt.DefaultCost)
	if err := db.CreateSubuser(context.Background(), database, "bob", string(subPassHash), 100); err != nil {
		t.Fatalf("failed to create bob: %v", err)
	}

	srv := New(cfg, database)

	loginUser := func(username, password, remoteIP string) *http.Cookie {
		t.Helper()
		form := strings.NewReader("username=" + username + "&password=" + password)
		req := httptest.NewRequest("POST", "/login", form)
		req.RemoteAddr = remoteIP
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.loginHandler(rr, req)
		if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/" {
			t.Fatalf("login(%s) failed: status=%d loc=%q", username, rr.Code, rr.Header().Get("Location"))
		}
		cookie := extractSessionCookie(rr)
		if cookie == nil {
			t.Fatalf("login(%s) did not set session cookie", username)
		}
		return cookie
	}

	assertSessionAccepted := func(c *http.Cookie, wantAccepted bool, label string) {
		t.Helper()
		req := httptest.NewRequest("GET", "/files", nil)
		req.AddCookie(c)
		rr := httptest.NewRecorder()
		srv.httpServer.Handler.ServeHTTP(rr, req)
		if wantAccepted {
			if rr.Code != http.StatusOK {
				t.Fatalf("%s: expected 200 OK with valid session, got %d (Location=%q)", label, rr.Code, rr.Header().Get("Location"))
			}
		} else {
			if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/login" {
				t.Fatalf("%s: expected 302 -> /login for revoked/invalid session, got %d (Location=%q)", label, rr.Code, rr.Header().Get("Location"))
			}
		}
	}

	// 1. Logout revokes the token server-side so a stolen copy cannot be reused
	token1 := loginUser("admin", "AdminPass123!", "198.51.100.1:1000")
	assertSessionAccepted(token1, true, "before logout")

	logoutReq := httptest.NewRequest("POST", "/logout", nil)
	logoutReq.AddCookie(token1)
	logoutRR := httptest.NewRecorder()
	srv.logoutHandler(logoutRR, logoutReq)
	assertSessionAccepted(token1, false, "after logout")

	// 2. Password change revokes old sessions while issuing a fresh valid session cookie to the caller
	token2 := loginUser("admin", "AdminPass123!", "198.51.100.2:1000")
	assertSessionAccepted(token2, true, "before password change")

	pwForm := strings.NewReader("current_password=AdminPass123!&new_password=AdminPass456!")
	pwReq := httptest.NewRequest("POST", "/settings/action/password", pwForm)
	pwReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	pwReq.AddCookie(token2)
	pwRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(pwRR, pwReq)
	if pwRR.Code != http.StatusFound {
		t.Fatalf("password change expected 302, got %d", pwRR.Code)
	}
	assertSessionAccepted(token2, false, "old token after password change")
	rotatedCookie := extractSessionCookie(pwRR)
	if rotatedCookie == nil {
		t.Fatalf("expected rotated session cookie after password change")
	}
	assertSessionAccepted(rotatedCookie, true, "rotated token after password change")

	// 3. Password reset via recovery code revokes existing sessions
	recCode, recHash, err := generateRecoveryCode()
	if err != nil {
		t.Fatalf("generateRecoveryCode: %v", err)
	}
	_ = db.UpdateRecoveryCode(context.Background(), database, "admin", recHash)

	resetForm := strings.NewReader(fmt.Sprintf("username=admin&recovery_code=%s&new_password=AdminPass789!&confirm_password=AdminPass789!", recCode))
	resetReq := httptest.NewRequest("POST", "/reset-password", resetForm)
	resetReq.RemoteAddr = "198.51.100.3:1000"
	resetReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resetRR := httptest.NewRecorder()
	srv.resetPasswordHandler(resetRR, resetReq)
	if resetRR.Code != http.StatusFound {
		t.Fatalf("password reset expected 302, got %d", resetRR.Code)
	}
	assertSessionAccepted(rotatedCookie, false, "after password reset")

	// 4. 2FA enable and disable revoke earlier sessions
	token3 := loginUser("admin", "AdminPass789!", "198.51.100.4:1000")
	assertSessionAccepted(token3, true, "before 2FA enable")

	genReq := httptest.NewRequest("POST", "/settings/2fa/generate", nil)
	genReq.AddCookie(token3)
	genRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(genRR, genReq)
	var genRes struct {
		Secret string `json:"secret"`
	}
	_ = json.Unmarshal(genRR.Body.Bytes(), &genRes)
	code, _ := totp.GenerateCode(genRes.Secret, time.Now())

	verReq := httptest.NewRequest("POST", "/settings/2fa/verify", strings.NewReader("code="+code))
	verReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verReq.AddCookie(token3)
	verRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(verRR, verReq)
	assertSessionAccepted(token3, false, "old token after 2FA enable")
	after2FACookie := extractSessionCookie(verRR)
	if after2FACookie == nil {
		t.Fatalf("expected rotated session cookie after 2FA enable")
	}
	assertSessionAccepted(after2FACookie, true, "rotated token after 2FA enable")

	// 5. User deletion revokes the deleted user's session immediately (and a recreated user with the same username cannot inherit an old token with mismatched ver)
	bobToken := loginUser("bob", "SubPass123!", "198.51.100.5:1000")
	assertSessionAccepted(bobToken, true, "bob before deletion")

	if err := db.DeleteUser(context.Background(), database, "bob"); err != nil {
		t.Fatalf("DeleteUser(bob) failed: %v", err)
	}
	assertSessionAccepted(bobToken, false, "bob after deletion")

	// 6. Token with wrong issuer or future iat is rejected
	wrongIssClaims := sessionClaims{
		Username: "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "wrong-issuer",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	wrongIssTok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, wrongIssClaims).SignedString([]byte(srv.cfg.JWTKey))
	assertSessionAccepted(&http.Cookie{Name: "session", Value: wrongIssTok}, false, "wrong issuer")
}

func TestPrivateFileAuthorization(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		EnvOnly:          true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	passHash, _ := bcrypt.GenerateFromPassword([]byte("Pass123!"), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(passHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}
	if err := db.CreateSubuser(context.Background(), database, "alice", string(passHash), 100); err != nil {
		t.Fatalf("failed to create alice: %v", err)
	}
	if err := db.CreateSubuser(context.Background(), database, "bob", string(passHash), 100); err != nil {
		t.Fatalf("failed to create bob: %v", err)
	}

	aliceUser, _ := db.GetUserByUsername(context.Background(), database, "alice")
	srv := New(cfg, database)

	if err := srv.storage.Save(context.Background(), "alice-private-key", strings.NewReader("alice-confidential-document")); err != nil {
		t.Fatalf("failed to save private file: %v", err)
	}
	if err := db.InsertFile(context.Background(), database, &db.File{
		OriginalName: "secret.txt",
		URLPath:      "alice-secret",
		Size:         int64(len("alice-confidential-document")),
		IsPrivate:    true,
		StorageType:  "local",
		StoragePath:  "alice-private-key",
		UserID:       aliceUser.ID,
	}); err != nil {
		t.Fatalf("failed to insert private file: %v", err)
	}

	mintCookieFor := func(username string) *http.Cookie {
		rr := httptest.NewRecorder()
		srv.setJWTCookie(rr, username)
		return extractSessionCookie(rr)
	}

	aliceCookie := mintCookieFor("alice")
	bobCookie := mintCookieFor("bob")
	adminCookie := mintCookieFor("admin")

	// 1. Unauthenticated request -> 404
	unauthReq := httptest.NewRequest("GET", "/f/alice-secret", nil)
	unauthRR := httptest.NewRecorder()
	srv.serveFileHandler(unauthRR, unauthReq)
	if unauthRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unauthenticated request to private file, got %d", unauthRR.Code)
	}

	// 2. Authenticated non-owner subuser (Bob) -> 404
	bobReq := httptest.NewRequest("GET", "/f/alice-secret", nil)
	bobReq.AddCookie(bobCookie)
	bobRR := httptest.NewRecorder()
	srv.serveFileHandler(bobRR, bobReq)
	if bobRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when bob requests alice's private file, got %d", bobRR.Code)
	}
	if strings.Contains(bobRR.Body.String(), "alice-confidential-document") {
		t.Fatalf("private file content leaked to non-owner bob!")
	}

	// 3. Owner (Alice) -> 200 OK with content
	aliceReq := httptest.NewRequest("GET", "/f/alice-secret", nil)
	aliceReq.AddCookie(aliceCookie)
	aliceRR := httptest.NewRecorder()
	srv.serveFileHandler(aliceRR, aliceReq)
	if aliceRR.Code != http.StatusOK || aliceRR.Body.String() != "alice-confidential-document" {
		t.Fatalf("expected 200 OK with private file content for owner alice, got %d (%q)", aliceRR.Code, aliceRR.Body.String())
	}

	// 4. Admin -> 200 OK with content
	adminReq := httptest.NewRequest("GET", "/f/alice-secret", nil)
	adminReq.AddCookie(adminCookie)
	adminRR := httptest.NewRecorder()
	srv.serveFileHandler(adminRR, adminReq)
	if adminRR.Code != http.StatusOK || adminRR.Body.String() != "alice-confidential-document" {
		t.Fatalf("expected 200 OK with private file content for admin, got %d (%q)", adminRR.Code, adminRR.Body.String())
	}

	// 5. After Alice logs out, her revoked token can no longer read her private file -> 404
	_ = db.IncrementSessionVersion(context.Background(), database, "alice")
	revokedReq := httptest.NewRequest("GET", "/f/alice-secret", nil)
	revokedReq.AddCookie(aliceCookie)
	revokedRR := httptest.NewRecorder()
	srv.serveFileHandler(revokedRR, revokedReq)
	if revokedRR.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when accessing private file with revoked session token, got %d", revokedRR.Code)
	}
}

func TestRecoveryGenerateWithTOTP(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
		EnvOnly:   true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	passHash, _ := bcrypt.GenerateFromPassword([]byte("AdminPass123!"), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(passHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "FileLine", AccountName: "admin"})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	_ = db.UpdateUserAuthData(context.Background(), database, "admin", key.Secret(), "[]")

	srv := New(cfg, database)
	ctxAdmin := context.WithValue(context.Background(), "username", "admin")

	// Wrong password and wrong TOTP -> 403 Forbidden
	badReq := httptest.NewRequest("POST", "/settings/recovery/generate", strings.NewReader(`{"current_password":"wrong","totp_code":"000000"}`)).WithContext(ctxAdmin)
	badReq.Header.Set("Content-Type", "application/json")
	badReq.Header.Set("Accept", "application/json")
	badRR := httptest.NewRecorder()
	srv.recoveryGenerateHandler(badRR, badReq)
	if badRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on wrong password/TOTP, got %d", badRR.Code)
	}

	// Valid TOTP code -> 200 OK
	validCode, _ := totp.GenerateCode(key.Secret(), time.Now())
	okReq := httptest.NewRequest("POST", "/settings/recovery/generate", strings.NewReader(fmt.Sprintf(`{"totp_code":%q}`, validCode))).WithContext(ctxAdmin)
	okReq.Header.Set("Content-Type", "application/json")
	okReq.Header.Set("Accept", "application/json")
	okRR := httptest.NewRecorder()
	srv.recoveryGenerateHandler(okRR, okReq)
	if okRR.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when re-authenticating with valid TOTP, got %d: %s", okRR.Code, okRR.Body.String())
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		ReverseProxy:     true, // enables HSTS
		EnvOnly:          true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "admin", "hash"); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}
	_ = db.UpdateUserEmbedConfig(context.Background(), database, "admin", db.EmbedConfig{
		Enabled:   true,
		SiteName:  "FileLine",
		ShowTitle: true,
	})
	adminUser, _ := db.GetUserByUsername(context.Background(), database, "admin")

	srv := New(cfg, database)
	_ = srv.storage.Save(context.Background(), "imgkey", strings.NewReader("\x89PNG\r\n\x1a\n"))
	_ = db.InsertFile(context.Background(), database, &db.File{
		OriginalName: "pic.png",
		URLPath:      "pic",
		Size:         8,
		StorageType:  "local",
		StoragePath:  "imgkey",
		UserID:       adminUser.ID,
	})

	// 1. Standard application route (/login) has strict security headers and clickjacking protection
	loginReq := httptest.NewRequest("GET", "/login", nil)
	loginRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(loginRR, loginReq)
	h := loginRR.Header()
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want 'nosniff'", got)
	}
	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want 'DENY'", got)
	}
	if got := h.Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
		t.Errorf("Referrer-Policy = %q, want 'strict-origin-when-cross-origin'", got)
	}
	if got := h.Get("Permissions-Policy"); got != "camera=(), microphone=(), geolocation=()" {
		t.Errorf("Permissions-Policy = %q, want 'camera=(), microphone=(), geolocation=()'", got)
	}
	if got := h.Get("Cross-Origin-Opener-Policy"); got != "same-origin" {
		t.Errorf("Cross-Origin-Opener-Policy = %q, want 'same-origin'", got)
	}
	if got := h.Get("Strict-Transport-Security"); got != "max-age=63072000; includeSubDomains" {
		t.Errorf("Strict-Transport-Security = %q, want 'max-age=63072000; includeSubDomains'", got)
	}
	csp := h.Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'self'", "form-action 'self'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP on /login missing directive %q: got %q", directive, csp)
		}
	}

	// 2. Raw file delivery (/f/pic?raw=1) overrides CSP with the strict sandbox CSP
	rawReq := httptest.NewRequest("GET", "/f/pic?raw=1", nil)
	rawRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rawRR, rawReq)
	rawCSP := rawRR.Header().Get("Content-Security-Policy")
	if !strings.HasPrefix(rawCSP, "sandbox;") {
		t.Errorf("expected /f/pic?raw=1 to retain sandbox CSP, got %q", rawCSP)
	}

	// 3. Embed viewer page (/f/pic without ?raw=1 when embed is enabled) allows frame-ancestors *
	embedReq := httptest.NewRequest("GET", "/f/pic", nil)
	embedRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(embedRR, embedReq)
	embedCSP := embedRR.Header().Get("Content-Security-Policy")
	if !strings.Contains(embedCSP, "frame-ancestors *") {
		t.Errorf("expected embed viewer page CSP to include 'frame-ancestors *', got %q", embedCSP)
	}
	if got := embedRR.Header().Get("X-Frame-Options"); got != "" {
		t.Errorf("expected X-Frame-Options to be omitted on embed viewer page, got %q", got)
	}
}

func TestCSRFCrossOriginProtectionAndCookieSecurity(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		Domain:           "files.example.com",
		Port:             443,
		ReverseProxy:     true,
		EnvOnly:          true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	passHash, _ := bcrypt.GenerateFromPassword([]byte("AdminPass123!"), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(passHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "FileLine", AccountName: "admin"})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}
	_ = db.UpdateUserAuthData(context.Background(), database, "admin", key.Secret(), "[]")

	srv := New(cfg, database)

	// 1. Cross-site POST request (Sec-Fetch-Site: cross-site or mismatched Origin) is blocked with 403 Forbidden
	csrfReq := httptest.NewRequest("POST", "https://files.example.com/login", strings.NewReader("username=admin&password=AdminPass123!"))
	csrfReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	csrfReq.Header.Set("Sec-Fetch-Site", "cross-site")
	csrfReq.Header.Set("Origin", "https://evil.example.net")
	csrfRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(csrfRR, csrfReq)
	if csrfRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-origin POST, got %d", csrfRR.Code)
	}

	// Same-site cross-origin subdomain POST (e.g. Origin: https://sub.example.com to Host: files.example.com) is also blocked
	subOriginReq := httptest.NewRequest("POST", "https://files.example.com/login", strings.NewReader("username=admin&password=AdminPass123!"))
	subOriginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	subOriginReq.Header.Set("Sec-Fetch-Site", "same-site")
	subOriginReq.Header.Set("Origin", "https://sub.example.com")
	subOriginRR := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(subOriginRR, subOriginReq)
	if subOriginRR.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-origin subdomain POST, got %d", subOriginRR.Code)
	}

	// 2. State-changing routes reject GET with 405 Method Not Allowed
	getLogoutReq := httptest.NewRequest("GET", "/logout", nil)
	getLogoutRR := httptest.NewRecorder()
	srv.logoutHandler(getLogoutRR, getLogoutReq)
	if getLogoutRR.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected GET /logout to return 405 Method Not Allowed, got %d", getLogoutRR.Code)
	}

	ctxAdmin := context.WithValue(context.Background(), "username", "admin")
	get2FAReq := httptest.NewRequest("GET", "/settings/2fa/generate", nil).WithContext(ctxAdmin)
	get2FARR := httptest.NewRecorder()
	srv.totpGenerateHandler(get2FARR, get2FAReq)
	if get2FARR.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected GET /settings/2fa/generate to return 405 Method Not Allowed, got %d", get2FARR.Code)
	}

	getAckReq := httptest.NewRequest("GET", "/settings/recovery/ack", nil).WithContext(ctxAdmin)
	getAckRR := httptest.NewRecorder()
	srv.recoveryAckHandler(getAckRR, getAckReq)
	if getAckRR.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected GET /settings/recovery/ack to return 405 Method Not Allowed, got %d", getAckRR.Code)
	}

	// 3. Auxiliary cookies (2fa_session, wa_login_session, wa_session) have Secure=true and SameSite=Strict
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader("username=admin&password=AdminPass123!"))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	srv.loginHandler(loginRR, loginReq)
	var twoFACookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == "2fa_session" {
			twoFACookie = c
		}
	}
	if twoFACookie == nil {
		t.Fatalf("expected 2fa_session cookie to be set")
	}
	if !twoFACookie.Secure || !twoFACookie.HttpOnly || twoFACookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("2fa_session cookie flags invalid: Secure=%v HttpOnly=%v SameSite=%v", twoFACookie.Secure, twoFACookie.HttpOnly, twoFACookie.SameSite)
	}

	waLoginReq := httptest.NewRequest("GET", "/webauthn/login/begin", nil)
	waLoginRR := httptest.NewRecorder()
	srv.webAuthnLoginBegin(waLoginRR, waLoginReq)
	var waLoginCookie *http.Cookie
	for _, c := range waLoginRR.Result().Cookies() {
		if c.Name == "wa_login_session" {
			waLoginCookie = c
		}
	}
	if waLoginCookie == nil {
		t.Fatalf("expected wa_login_session cookie to be set")
	}
	if !waLoginCookie.Secure || !waLoginCookie.HttpOnly || waLoginCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("wa_login_session cookie flags invalid: Secure=%v HttpOnly=%v SameSite=%v", waLoginCookie.Secure, waLoginCookie.HttpOnly, waLoginCookie.SameSite)
	}

	waRegReq := httptest.NewRequest("GET", "/webauthn/register/begin", nil).WithContext(ctxAdmin)
	waRegRR := httptest.NewRecorder()
	srv.webAuthnRegisterBegin(waRegRR, waRegReq)
	var waRegCookie *http.Cookie
	for _, c := range waRegRR.Result().Cookies() {
		if c.Name == "wa_session" {
			waRegCookie = c
		}
	}
	if waRegCookie == nil {
		t.Fatalf("expected wa_session cookie to be set")
	}
	if !waRegCookie.Secure || !waRegCookie.HttpOnly || waRegCookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("wa_session cookie flags invalid: Secure=%v HttpOnly=%v SameSite=%v", waRegCookie.Secure, waRegCookie.HttpOnly, waRegCookie.SameSite)
	}
}

func TestSecretsProtectionAtRestAndInUI(t *testing.T) {
	t.Setenv("FL_DATA_KEY", "test-master-encryption-key-for-totp-at-rest")
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "config.json")
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		PostgresURL:      "postgres://pguser:SuperSecretPgPass!@db.internal:5432/fileline?sslmode=require",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		S3AccessKey:      "AKIA_PRIMARY",
		S3SecretKey:      "PRIMARY_S3_SUPER_SECRET_KEY_VALUE",
		JWTKey:           "JWT_SIGNING_SECRET_KEY_32_BYTES_MINIMUM_XYZ",
		Drives: []config.Drive{
			{
				ID:          "s3_backup",
				Name:        "Backup S3",
				Type:        "s3",
				Enabled:     true,
				S3Endpoint:  "s3.example.com",
				S3Region:    "us-east-1",
				S3Bucket:    "backups",
				S3AccessKey: "AKIA_DRIVE_1",
				S3SecretKey: "DRIVE_1_SUPER_SECRET_KEY_VALUE",
				S3UseSSL:    true,
			},
		},
	}
	if err := cfg.Save(cfgPath); err != nil {
		t.Fatalf("cfg.Save: %v", err)
	}
	st, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("os.Stat(config.json): %v", err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("expected config.json mode 0600, got %04o", perm)
	}

	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	passHash, _ := bcrypt.GenerateFromPassword([]byte("AdminPass123!"), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(passHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	// 1. TOTP secret is encrypted with AES-GCM at rest in the database and transparently decrypted on load
	plainTOTP := "JBSWY3DPEHPK3PXP"
	if err := db.UpdateUserAuthData(context.Background(), database, "admin", plainTOTP, "[]"); err != nil {
		t.Fatalf("UpdateUserAuthData: %v", err)
	}
	var rawStoredTOTP string
	if err := database.QueryRow("SELECT totp_secret FROM users WHERE username = 'admin'").Scan(&rawStoredTOTP); err != nil {
		t.Fatalf("SELECT totp_secret: %v", err)
	}
	if rawStoredTOTP == plainTOTP || strings.Contains(rawStoredTOTP, plainTOTP) {
		t.Fatalf("expected totp_secret in DB to be encrypted, but found plaintext %q", rawStoredTOTP)
	}
	if !strings.HasPrefix(rawStoredTOTP, "enc:v1:") {
		t.Fatalf("expected encrypted totp_secret prefix 'enc:v1:', got %q", rawStoredTOTP)
	}
	loadedUser, err := db.GetUserByUsername(context.Background(), database, "admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if loadedUser.TOTPSecret != plainTOTP {
		t.Fatalf("expected decrypted TOTPSecret %q, got %q", plainTOTP, loadedUser.TOTPSecret)
	}
	loadedByID, err := db.GetUserByID(context.Background(), database, loadedUser.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if loadedByID.TOTPSecret != plainTOTP {
		t.Fatalf("expected GetUserByID decrypted TOTPSecret %q, got %q", plainTOTP, loadedByID.TOTPSecret)
	}

	// 2. /settings/storage and /settings HTML never leak S3SecretKey, drive S3SecretKey, JWTKey, or PostgresURL
	srv := New(cfg, database)
	ctxAdmin := context.WithValue(context.Background(), "username", "admin")

	storageReq := httptest.NewRequest("GET", "/settings/storage", nil).WithContext(ctxAdmin)
	storageRR := httptest.NewRecorder()
	srv.settingsStorageHandler(storageRR, storageReq)
	if storageRR.Code != http.StatusOK {
		t.Fatalf("GET /settings/storage status = %d", storageRR.Code)
	}
	body := storageRR.Body.String()
	for _, secret := range []string{
		"PRIMARY_S3_SUPER_SECRET_KEY_VALUE",
		"DRIVE_1_SUPER_SECRET_KEY_VALUE",
		"JWT_SIGNING_SECRET_KEY_32_BYTES_MINIMUM_XYZ",
		"SuperSecretPgPass!",
	} {
		if strings.Contains(body, secret) {
			t.Errorf("secret %q leaked into /settings/storage HTML response", secret)
		}
	}
	if !strings.Contains(body, `s3_secret_set`) {
		t.Errorf("expected sanitized DrivesJSON to include s3_secret_set")
	}
	if strings.Contains(body, `s3_secret_key": "`) || strings.Contains(body, `s3_secret_key\":\"`) {
		t.Errorf("expected DrivesJSON not to include any s3_secret_key field")
	}

	// 3. Submitting storage settings with blank drive s3_secret_key preserves existing drive secret
	submittedDrives := `[{"id":"s3_backup","name":"Backup S3 Renamed","type":"s3","enabled":true,"s3_endpoint":"s3.example.com","s3_region":"us-east-1","s3_bucket":"backups","s3_access_key":"AKIA_DRIVE_1","s3_secret_key":"","s3_use_ssl":true}]`
	form := "storage_type=local&local_path=" + tempDir + "&max_upload_size_mb=512&chunk_threshold_mb=50&chunk_size_mb=10&drives_json=" + submittedDrives
	saveReq := httptest.NewRequest("POST", "/settings/action/storage", strings.NewReader(form)).WithContext(ctxAdmin)
	saveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	saveRR := httptest.NewRecorder()
	srv.settingsActionHandler(saveRR, saveReq)
	if saveRR.Code != http.StatusFound {
		t.Fatalf("POST /settings/action/storage status = %d", saveRR.Code)
	}
	if len(srv.cfg.Drives) != 1 || srv.cfg.Drives[0].S3SecretKey != "DRIVE_1_SUPER_SECRET_KEY_VALUE" {
		t.Fatalf("expected existing drive S3SecretKey to be preserved when submitted blank, got %+v", srv.cfg.Drives)
	}
	if srv.cfg.Drives[0].Name != "Backup S3 Renamed" {
		t.Fatalf("expected drive Name to update, got %q", srv.cfg.Drives[0].Name)
	}
}

func TestTTLStoreBoundsAndWebAuthnRateLimit(t *testing.T) {
	// 1. Generic ttlStore enforces TTL expiration on Load/LoadAndDelete and evicts oldest entries when max capacity is exceeded
	store := newTTLStore[string, int](50*time.Millisecond, 3)
	store.Store("k1", 1)
	time.Sleep(5 * time.Millisecond)
	store.Store("k2", 2)
	time.Sleep(5 * time.Millisecond)
	store.Store("k3", 3)
	if store.Len() != 3 {
		t.Fatalf("expected store len 3, got %d", store.Len())
	}

	// Storing a 4th item evicts the oldest entry ("k1")
	store.Store("k4", 4)
	if store.Len() != 3 {
		t.Fatalf("expected store len capped at 3 after eviction, got %d", store.Len())
	}
	if _, ok := store.Load("k1"); ok {
		t.Fatalf("expected oldest key 'k1' to be evicted when max capacity reached")
	}
	if v, ok := store.Load("k4"); !ok || v != 4 {
		t.Fatalf("expected 'k4' to remain in store with value 4, got %v (ok=%v)", v, ok)
	}

	// Wait for TTL to expire -> Load and LoadAndDelete return false and prune expired entries
	time.Sleep(60 * time.Millisecond)
	if _, ok := store.Load("k2"); ok {
		t.Fatalf("expected 'k2' to expire after TTL")
	}
	if _, ok := store.LoadAndDelete("k3"); ok {
		t.Fatalf("expected 'k3' to expire after TTL on LoadAndDelete")
	}
	store.Sweep(time.Now())
	if store.Len() != 0 {
		t.Fatalf("expected store len 0 after Sweep of expired entries, got %d", store.Len())
	}

	// 2. /webauthn/login/begin is rate-limited per IP and webAuthnTempStore stays bounded
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
		EnvOnly:   true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "admin", "hash"); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	srv := New(cfg, database)
	// First 19 requests (up to loginMaxAttempts*2 - 1) from the same IP are allowed by the limiter
	for i := 1; i <= 19; i++ {
		req := httptest.NewRequest("GET", "/webauthn/login/begin?username=admin", nil)
		req.RemoteAddr = "198.51.100.77:12345"
		rr := httptest.NewRecorder()
		srv.webAuthnLoginBegin(rr, req)
		if rr.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpected 429 TooManyRequests", i)
		}
	}
	// 20th request (loginMaxAttempts*2) from the same IP is blocked with 429 TooManyRequests before allocating any session state
	req20 := httptest.NewRequest("GET", "/webauthn/login/begin?username=admin", nil)
	req20.RemoteAddr = "198.51.100.77:12345"
	rr20 := httptest.NewRecorder()
	srv.webAuthnLoginBegin(rr20, req20)
	if rr20.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 20th /webauthn/login/begin request to be rate-limited with 429, got %d", rr20.Code)
	}
}

func TestInputValidationAndPasswordPolicy(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		MaxUploadSizeMB:  10,
		Theme:            "dark",
		DefaultLanguage:  "en",
		Accent:           "indigo",
		CustomAccentHex:  "#5865f2",
		EnvOnly:          true,
		Drives: []config.Drive{
			{ID: "drive_enabled", Name: "Enabled Drive", Type: "local", LocalStoragePath: tempDir, Enabled: true},
			{ID: "drive_disabled", Name: "Disabled Drive", Type: "local", LocalStoragePath: tempDir, Enabled: false},
		},
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	adminPass := "StrongAdminPass99!"
	passHash, _ := bcrypt.GenerateFromPassword([]byte(adminPass), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(passHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	srv := New(cfg, database)
	ctxAdmin := context.WithValue(context.Background(), "username", "admin")

	// 1. Password policy: empty, <8 chars, >72 bytes, or common breached passwords rejected on password change
	badPasswords := []string{
		"",
		"short1!",
		"password",
		"12345678",
		"qwerty123",
		strings.Repeat("A", 73),
	}
	for _, bad := range badPasswords {
		form := fmt.Sprintf("current_password=%s&new_password=%s", adminPass, bad)
		req := httptest.NewRequest("POST", "/settings/action/password", strings.NewReader(form)).WithContext(ctxAdmin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.settingsActionHandler(rr, req)
		loc := rr.Header().Get("Location")
		if rr.Code != http.StatusFound || !strings.Contains(loc, "error=") {
			t.Errorf("password change with invalid new_password %q: expected 302 with error=, got %d (Location=%q)", bad, rr.Code, loc)
		}
	}
	// Verify admin password was NOT overwritten by any of the bad passwords
	adminAfter, _ := db.GetUserByUsername(context.Background(), database, "admin")
	if bcrypt.CompareHashAndPassword([]byte(adminAfter.PasswordHash), []byte(adminPass)) != nil {
		t.Fatalf("admin password hash was unexpectedly modified by invalid password change request")
	}

	// 2. Subuser creation validates username format, password policy, and rejects negative quota
	badUserForms := []string{
		"new_username=ab&new_password=ValidPassword99!&new_quota=5",
		"new_username=bad+space&new_password=ValidPassword99!&new_quota=5",
		"new_username=%3Cscript%3E&new_password=ValidPassword99!&new_quota=5",
		"new_username=valid_user&new_password=password123&new_quota=5",
		"new_username=valid_user&new_password=short&new_quota=5",
		"new_username=valid_user&new_password=ValidPassword99!&new_quota=-10",
	}
	for _, form := range badUserForms {
		req := httptest.NewRequest("POST", "/settings/users/add", strings.NewReader(form)).WithContext(ctxAdmin)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.addUserHandler(rr, req)
		loc := rr.Header().Get("Location")
		if rr.Code != http.StatusFound || !strings.Contains(loc, "error=") {
			t.Errorf("addUserHandler(%s): expected 302 with error=, got %d (Location=%q)", form, rr.Code, loc)
		}
	}
	if _, err := db.GetUserByUsername(context.Background(), database, "valid_user"); err == nil {
		t.Errorf("expected invalid subuser creation requests not to create 'valid_user'")
	}

	// 3. Appearance & Embed settings validate theme, language, and hex color format
	badThemeReq := httptest.NewRequest("POST", "/settings/action/appearance", strings.NewReader("theme=neon-pink&language=xx-invalid&accent=custom&custom_accent_hex=javascript:alert(1)")).WithContext(ctxAdmin)
	badThemeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badThemeRR := httptest.NewRecorder()
	srv.settingsActionHandler(badThemeRR, badThemeReq)
	if srv.cfg.Theme != "dark" || srv.cfg.DefaultLanguage != "en" || srv.cfg.CustomAccentHex != "#5865f2" {
		t.Errorf("expected invalid theme/language/custom_accent_hex to be ignored, got Theme=%q DefaultLanguage=%q Hex=%q",
			srv.cfg.Theme, srv.cfg.DefaultLanguage, srv.cfg.CustomAccentHex)
	}

	// 4. Upload and edit validate url_path, drive_id, and return 409 Conflict on duplicate url_path
	// 4a. Unconfigured or disabled drive_id rejected on chunk upload init
	for _, badDrive := range []string{"nonexistent_drive", "drive_disabled"} {
		body, _ := json.Marshal(map[string]interface{}{
			"file_name":    "doc.txt",
			"total_size":   4,
			"total_chunks": 1,
			"drive_id":     badDrive,
		})
		req := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(body)).WithContext(ctxAdmin)
		rr := httptest.NewRecorder()
		srv.chunkUploadInitHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for drive_id=%q, got %d", badDrive, rr.Code)
		}
	}

	// 4b. Invalid url_path (slashes, spaces, traversal, query chars) rejected on chunk upload init
	for _, badURLPath := range []string{"a/b", "..", ".", "bad space", "foo?bar=1", "foo#bar"} {
		body, _ := json.Marshal(map[string]interface{}{
			"file_name":    "doc.txt",
			"total_size":   4,
			"total_chunks": 1,
			"url_path":     badURLPath,
		})
		req := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(body)).WithContext(ctxAdmin)
		rr := httptest.NewRecorder()
		srv.chunkUploadInitHandler(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("expected 400 for invalid url_path=%q, got %d", badURLPath, rr.Code)
		}
	}

	// 4c. Duplicate url_path returns 409 Conflict on upload and edit
	if err := srv.storage.Save(context.Background(), "firstkey", strings.NewReader("hello")); err != nil {
		t.Fatalf("save firstkey: %v", err)
	}
	if err := db.InsertFile(context.Background(), database, &db.File{
		UserID:       adminAfter.ID,
		OriginalName: "first.txt",
		URLPath:      "taken-slug",
		Size:         5,
		StorageType:  "local",
		StoragePath:  "firstkey",
	}); err != nil {
		t.Fatalf("insert first file: %v", err)
	}
	if err := srv.storage.Save(context.Background(), "secondkey", strings.NewReader("world")); err != nil {
		t.Fatalf("save secondkey: %v", err)
	}
	if err := db.InsertFile(context.Background(), database, &db.File{
		UserID:       adminAfter.ID,
		OriginalName: "second.txt",
		URLPath:      "second-slug",
		Size:         5,
		StorageType:  "local",
		StoragePath:  "secondkey",
	}); err != nil {
		t.Fatalf("insert second file: %v", err)
	}
	secondFile, _ := db.GetFileByURL(context.Background(), database, "second-slug")

	// Chunk upload init with already-taken url_path -> 409 Conflict
	dupInitBody, _ := json.Marshal(map[string]interface{}{
		"file_name":    "third.txt",
		"total_size":   5,
		"total_chunks": 1,
		"url_path":     "taken-slug",
	})
	dupInitReq := httptest.NewRequest("POST", "/api/upload/init", bytes.NewReader(dupInitBody)).WithContext(ctxAdmin)
	dupInitRR := httptest.NewRecorder()
	srv.chunkUploadInitHandler(dupInitRR, dupInitReq)
	if dupInitRR.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict for duplicate url_path on chunkUploadInit, got %d", dupInitRR.Code)
	}

	// Editing secondFile to use "taken-slug" -> 409 Conflict
	editDupForm := fmt.Sprintf("id=%d&custom_name=Second+File&url_path=taken-slug", secondFile.ID)
	editDupReq := httptest.NewRequest("POST", "/edit", strings.NewReader(editDupForm)).WithContext(ctxAdmin)
	editDupReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	editDupRR := httptest.NewRecorder()
	srv.editFileHandler(editDupRR, editDupReq)
	if editDupRR.Code != http.StatusConflict {
		t.Errorf("expected 409 Conflict when editing file to duplicate url_path, got %d", editDupRR.Code)
	}

	// Editing secondFile with invalid url_path -> 400 BadRequest
	editBadForm := fmt.Sprintf("id=%d&custom_name=Second+File&url_path=../bad/slug", secondFile.ID)
	editBadReq := httptest.NewRequest("POST", "/edit", strings.NewReader(editBadForm)).WithContext(ctxAdmin)
	editBadReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	editBadRR := httptest.NewRecorder()
	srv.editFileHandler(editBadRR, editBadReq)
	if editBadRR.Code != http.StatusBadRequest {
		t.Errorf("expected 400 BadRequest when editing file with invalid url_path, got %d", editBadRR.Code)
	}
}

func TestSecurityAuditLoggingInProductionAndLogInjection(t *testing.T) {
	var stdoutBuf, stderrBuf bytes.Buffer
	logger.SetOutput(&stdoutBuf, &stderrBuf)
	logger.SetDebug(false) // production mode (debug OFF)
	defer func() {
		logger.ResetOutput()
		logger.SetDebug(false)
	}()

	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
		Debug:     false,
		EnvOnly:   true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	passHash, _ := bcrypt.GenerateFromPassword([]byte("CorrectPassword123!"), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(passHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}

	srv := New(cfg, database)
	stdoutBuf.Reset()

	// Failed login with CR/LF log-injection attempt in username when Debug is false
	injectedUser := "attacker\r\n2026/10/17 00:00:00 [INFO] [AUDIT] [ACTION] Forged log entry"
	form := urlValuesEncode(map[string]string{
		"username": injectedUser,
		"password": "WrongPassword",
	})
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form))
	req.RemoteAddr = "198.51.100.77:54321"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.loginHandler(rr, req)

	out := strings.TrimSpace(stdoutBuf.String())
	if out == "" {
		t.Fatalf("expected failed login security event to be logged even when debug=false, got empty log")
	}
	lines := strings.Split(out, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected CR/LF in username to be escaped into a single log line, got %d lines:\n%s", len(lines), out)
	}
	if !strings.Contains(lines[0], `attacker\r\n`) {
		t.Errorf("expected escaped \\r\\n in audit log, got: %s", lines[0])
	}
	if !strings.Contains(lines[0], `"category":"audit"`) {
		t.Errorf("expected structured slog JSON with category=audit, got: %s", lines[0])
	}
	if strings.Contains(lines[0], "WrongPassword") {
		t.Errorf("password must never be logged in audit trail: %s", lines[0])
	}
}

func urlValuesEncode(m map[string]string) string {
	var parts []string
	for k, v := range m {
		parts = append(parts, k+"="+strings.ReplaceAll(strings.ReplaceAll(v, "\r", "%0D"), "\n", "%0A"))
	}
	return strings.Join(parts, "&")
}

func TestTrustedProxyClientIPAndHostHeaderProtection(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DBType:           "sqlite",
		SQLiteURL:        ":memory:",
		StorageType:      "local",
		LocalStoragePath: tempDir,
		Domain:           "files.example.com",
		Port:             8080,
		ReverseProxy:     true,
		TrustedProxies:   []string{"10.0.0.0/8", "127.0.0.1/32"},
		EnvOnly:          true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	passHash, _ := bcrypt.GenerateFromPassword([]byte("CorrectPassword123!"), bcrypt.DefaultCost)
	if err := db.CreateAdmin(context.Background(), database, "admin", string(passHash)); err != nil {
		t.Fatalf("failed to create admin: %v", err)
	}
	_ = db.UpdateUserEmbedConfig(context.Background(), database, "admin", db.EmbedConfig{
		Enabled:   true,
		SiteName:  "FileLine",
		ShowTitle: true,
	})
	adminUser, _ := db.GetUserByUsername(context.Background(), database, "admin")

	srv := New(cfg, database)
	_ = srv.storage.Save(context.Background(), "imgkey", strings.NewReader("\x89PNG\r\n\x1a\n"))
	_ = db.InsertFile(context.Background(), database, &db.File{
		OriginalName: "clip.png",
		URLPath:      "clip",
		Size:         8,
		StorageType:  "local",
		StoragePath:  "imgkey",
		UserID:       adminUser.ID,
	})

	// 1. Spoofed leftmost X-Forwarded-For from a trusted proxy:
	//    Client spoofs "X-Forwarded-For: 1.2.3.4", proxy (10.0.0.2) appends real client IP "198.51.100.44, 10.0.0.5".
	//    clientIP MUST return the rightmost untrusted hop ("198.51.100.44"), never the attacker-controlled leftmost "1.2.3.4".
	rTrusted := httptest.NewRequest("GET", "/", nil)
	rTrusted.RemoteAddr = "10.0.0.2:43210"
	rTrusted.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.44, 10.0.0.5")
	if got := srv.clientIP(rTrusted); got != "198.51.100.44" {
		t.Fatalf("clientIP with trusted proxy and spoofed leftmost XFF = %q, want rightmost untrusted hop '198.51.100.44'", got)
	}

	// 2. Direct connection from an UNTRUSTED peer (not in TrustedProxies CIDR):
	//    X-Forwarded-For and X-Real-IP MUST be ignored even when ReverseProxy is true.
	rUntrusted := httptest.NewRequest("GET", "/", nil)
	rUntrusted.RemoteAddr = "203.0.113.99:55555"
	rUntrusted.Header.Set("X-Forwarded-For", "1.2.3.4")
	rUntrusted.Header.Set("X-Real-IP", "5.6.7.8")
	if got := srv.clientIP(rUntrusted); got != "203.0.113.99" {
		t.Fatalf("clientIP from untrusted peer = %q, want direct peer IP '203.0.113.99'", got)
	}

	// 3. Rate limiter cannot be bypassed by rotating spoofed leftmost X-Forwarded-For values behind a trusted proxy
	for i := 1; i <= loginMaxAttempts; i++ {
		req := httptest.NewRequest("POST", "/login", strings.NewReader("username=admin&password=WrongPassword"))
		req.RemoteAddr = "10.0.0.2:40000"
		// Attacker rotates leftmost XFF on every request, while proxy appends real client IP 198.51.100.88
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d, 198.51.100.88", i))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		srv.loginHandler(rr, req)
		if i == loginMaxAttempts && rr.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429 on %dth failed attempt despite rotating leftmost X-Forwarded-For, got %d", i, rr.Code)
		}
	}

	// 4. Host-header & X-Forwarded-Proto poisoning protection on embed / oEmbed URLs:
	//    Attacker sends Host: evil.attacker.com and X-Forwarded-Proto: javascript; response URLs must use canonical Domain (https://files.example.com).
	embedReq := httptest.NewRequest("GET", "/f/clip", nil)
	embedReq.Host = "evil.attacker.com"
	embedReq.Header.Set("X-Forwarded-Host", "evil.attacker.com")
	embedReq.Header.Set("X-Forwarded-Proto", "http")
	embedRR := httptest.NewRecorder()
	srv.serveFileHandler(embedRR, embedReq)
	if embedRR.Code != http.StatusOK {
		t.Fatalf("GET /f/clip status = %d", embedRR.Code)
	}
	body := embedRR.Body.String()
	if strings.Contains(body, "evil.attacker.com") {
		t.Fatalf("Host header poisoning succeeded: evil.attacker.com appeared in embed HTML:\n%s", body)
	}
	if !strings.Contains(body, "https://files.example.com/f/clip?raw=1") {
		t.Errorf("expected canonical https://files.example.com/f/clip?raw=1 in embed HTML, got:\n%s", body)
	}

	oembedReq := httptest.NewRequest("GET", "/oembed?f=clip", nil)
	oembedReq.Host = "evil.attacker.com"
	oembedRR := httptest.NewRecorder()
	srv.oembedHandler(oembedRR, oembedReq)
	if strings.Contains(oembedRR.Body.String(), "evil.attacker.com") {
		t.Fatalf("Host header poisoning succeeded in /oembed response: %s", oembedRR.Body.String())
	}
	if !strings.Contains(oembedRR.Body.String(), "https://files.example.com") {
		t.Errorf("expected canonical https://files.example.com in /oembed response, got: %s", oembedRR.Body.String())
	}
}

func TestWebAuthnCredentialPersistenceAndErrorSanitization(t *testing.T) {
	cfg := &config.Config{
		DBType:    "sqlite",
		SQLiteURL: ":memory:",
		EnvOnly:   true,
	}
	database, err := db.InitDB(context.Background(), cfg)
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()
	if err := db.Migrate(context.Background(), database, "sqlite"); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}
	if err := db.CreateAdmin(context.Background(), database, "wauser", "hash"); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	credID := []byte("cred-id-sec20")
	initialPasskeys := []auth.Passkey{
		{
			Name: "Hardware Key",
			Credential: webauthn.Credential{
				ID: credID,
				Authenticator: webauthn.Authenticator{
					SignCount:    1,
					CloneWarning: false,
				},
			},
		},
	}
	initialJSON, _ := json.Marshal(initialPasskeys)
	if err := db.UpdateUserAuthData(context.Background(), database, "wauser", "", string(initialJSON)); err != nil {
		t.Fatalf("UpdateUserAuthData: %v", err)
	}
	dbUser, _ := db.GetUserByUsername(context.Background(), database, "wauser")

	// 1. updateUserPasskeyCredential persists updated SignCount, CloneWarning, and Flags while preserving passkey Name
	updatedCred := &webauthn.Credential{
		ID: credID,
		Flags: webauthn.CredentialFlags{
			BackupEligible: true,
			BackupState:    true,
		},
		Authenticator: webauthn.Authenticator{
			SignCount:    42,
			CloneWarning: false,
		},
	}
	if err := updateUserPasskeyCredential(context.Background(), database, dbUser, updatedCred); err != nil {
		t.Fatalf("updateUserPasskeyCredential failed: %v", err)
	}

	reloadedUser, err := db.GetUserByUsername(context.Background(), database, "wauser")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	var savedPasskeys []auth.Passkey
	if err := json.Unmarshal([]byte(reloadedUser.WebAuthnData), &savedPasskeys); err != nil {
		t.Fatalf("Unmarshal WebAuthnData: %v", err)
	}
	if len(savedPasskeys) != 1 {
		t.Fatalf("expected 1 passkey, got %d", len(savedPasskeys))
	}
	if savedPasskeys[0].Name != "Hardware Key" {
		t.Errorf("expected passkey name 'Hardware Key' preserved, got %q", savedPasskeys[0].Name)
	}
	if savedPasskeys[0].Credential.Authenticator.SignCount != 42 {
		t.Errorf("expected persisted SignCount 42, got %d", savedPasskeys[0].Credential.Authenticator.SignCount)
	}
	if !savedPasskeys[0].Credential.Flags.BackupEligible || !savedPasskeys[0].Credential.Flags.BackupState {
		t.Errorf("expected persisted BackupEligible/BackupState flags to be true, got %+v", savedPasskeys[0].Credential.Flags)
	}

	// 2. 20: webAuthnLoginFinish deletes the challenge session on the first finish attempt so it cannot be replayed
	srv := New(cfg, database)
	srv.webAuthnTempStore.Store("login-sess-1", webauthn.SessionData{Challenge: "ch-1"})

	loginFinReq := httptest.NewRequest("POST", "/webauthn/login/finish", strings.NewReader(`{"invalid":"assertion"}`))
	loginFinReq.AddCookie(&http.Cookie{Name: "wa_login_session", Value: "login-sess-1"})
	loginFinRR := httptest.NewRecorder()
	srv.webAuthnLoginFinish(loginFinRR, loginFinReq)
	if loginFinRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 BadRequest on invalid WebAuthn login finish, got %d", loginFinRR.Code)
	}
	if _, stillExists := srv.webAuthnTempStore.Load("login-sess-1"); stillExists {
		t.Fatalf("expected wa_login_session to be deleted on finish attempt to prevent replay")
	}

	// 3. webAuthnRegisterFinish returns a generic message and does not leak internal protocol/CBOR parsing errors to the client
	srv.webAuthnTempStore.Store("reg-sess-1", webauthn.SessionData{Challenge: "ch-reg"})
	ctxUser := context.WithValue(context.Background(), "username", "wauser")
	regFinReq := httptest.NewRequest("POST", "/webauthn/register/finish", strings.NewReader(`{"id":"bad","rawId":"!!!not-base64!!!"}`)).WithContext(ctxUser)
	regFinReq.AddCookie(&http.Cookie{Name: "wa_session", Value: "reg-sess-1"})
	regFinRR := httptest.NewRecorder()
	srv.webAuthnRegisterFinish(regFinRR, regFinReq)
	if regFinRR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 BadRequest on invalid WebAuthn registration finish, got %d", regFinRR.Code)
	}
	respBody := strings.TrimSpace(regFinRR.Body.String())
	if respBody != "Invalid passkey registration" {
		t.Errorf("expected generic error 'Invalid passkey registration', got %q (internal error leaked)", respBody)
	}
}
