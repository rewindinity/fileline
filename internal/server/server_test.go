package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fileline/internal/config"
	"fileline/internal/db"
	"fileline/internal/logger"

	"github.com/pquerna/otp/totp"
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
