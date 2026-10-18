package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestSetDebug(t *testing.T) {
	SetDebug(false)
	if IsDebug() {
		t.Fatal("expected debug false")
	}
	SetDebug(true)
	if !IsDebug() {
		t.Fatal("expected debug true")
	}
	SetDebug(false)
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024 * 5, "5.0 GB"},
	}
	for _, tc := range tests {
		got := FormatBytes(tc.bytes)
		if got != tc.expected {
			t.Errorf("FormatBytes(%d) = %s; want %s", tc.bytes, got, tc.expected)
		}
	}
}

func TestLoggerOutputs(t *testing.T) {
	var stdoutBuf, stderrBuf bytes.Buffer
	SetOutput(&stdoutBuf, &stderrBuf)
	defer func() {
		ResetOutput()
		SetDebug(false)
	}()

	// With debug OFF: Info, Error, and Action (security audit events) MUST be logged; Debug and HTTP access logs stay hidden
	SetDebug(false)
	Info("Server started")
	Error("Database error")
	Debug("Hidden debug")
	Action("Failed login attempt for user 'alice'")
	Audit("login_failed", slog.String("user", "bob"), slog.String("ip", "203.0.113.5"))
	HTTP("GET", "/test", 200, 5*time.Millisecond, "127.0.0.1", "admin")

	outOff := stdoutBuf.String()
	if !strings.Contains(outOff, "[INFO] Server started") {
		t.Errorf("expected [INFO] Server started in stdout, got: %s", outOff)
	}
	if !strings.Contains(outOff, "Failed login attempt for user 'alice'") || !strings.Contains(outOff, `"category":"audit"`) {
		t.Errorf("expected security audit Action to be logged even when debug is off, got: %s", outOff)
	}
	if !strings.Contains(outOff, `"event":"login_failed"`) || !strings.Contains(outOff, `"user":"bob"`) {
		t.Errorf("expected structured Audit event in stdout when debug is off, got: %s", outOff)
	}
	if strings.Contains(outOff, "Hidden debug") || strings.Contains(outOff, "[HTTP]") {
		t.Errorf("unexpected debug/HTTP logs when debug is off: %s", outOff)
	}
	if !strings.Contains(stderrBuf.String(), "[ERROR] Database error") {
		t.Errorf("expected [ERROR] Database error in stderr, got: %s", stderrBuf.String())
	}

	stdoutBuf.Reset()
	stderrBuf.Reset()

	// With debug ON
	SetDebug(true)
	Debug("Visible debug")
	Action("User logged in")
	HTTP("POST", "/upload", 200, 10*time.Millisecond, "127.0.0.1", "admin")

	out := stdoutBuf.String()
	if !strings.Contains(out, "[DEBUG] Visible debug") {
		t.Errorf("expected [DEBUG] Visible debug in stdout, got: %s", out)
	}
	if !strings.Contains(out, "[ACTION] User logged in") {
		t.Errorf("expected [ACTION] User logged in in stdout, got: %s", out)
	}
	if !strings.Contains(out, "[DEBUG] [HTTP] POST /upload -> 200") {
		t.Errorf("expected [DEBUG] [HTTP] log in stdout, got: %s", out)
	}
}

func TestLogInjectionPrevention(t *testing.T) {
	var stdoutBuf, stderrBuf bytes.Buffer
	SetOutput(&stdoutBuf, &stderrBuf)
	defer func() {
		ResetOutput()
		SetDebug(false)
	}()

	SetDebug(false)
	// Attacker tries to forge a second log line using CR/LF and NUL bytes in username
	maliciousUser := "evil\r\n2026/10/17 12:00:00 [INFO] [ACTION] User 'admin' logged in successfully\x00"
	Action("Failed login attempt for username '%s'", maliciousUser)
	Audit("login_failed", slog.String("user", maliciousUser))

	lines := strings.Split(strings.TrimSpace(stdoutBuf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected exactly 2 log lines (CR/LF must be escaped, preventing log injection), got %d lines:\n%s", len(lines), stdoutBuf.String())
	}
	for i, line := range lines {
		if strings.Contains(line, "\r") || strings.Contains(line, "\x00") {
			t.Errorf("line %d contains raw CR or NUL control character: %q", i, line)
		}
		// Verify the embedded slog JSON payload is valid JSON
		idx := strings.Index(line, " — {")
		if idx == -1 {
			t.Fatalf("line %d missing structured slog JSON payload: %s", i, line)
		}
		jsonPart := line[idx+len(" — "):]
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(jsonPart), &parsed); err != nil {
			t.Errorf("line %d invalid slog JSON (%v): %s", i, err, jsonPart)
		}
	}
}
