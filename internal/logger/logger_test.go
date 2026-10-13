package logger

import (
	"bytes"
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

	// With debug OFF
	SetDebug(false)
	Info("Server started")
	Error("Database error")
	Debug("Hidden debug")
	Action("Hidden action")
	HTTP("GET", "/test", 200, 5*time.Millisecond, "127.0.0.1", "admin")

	if !strings.Contains(stdoutBuf.String(), "[INFO] Server started") {
		t.Errorf("expected [INFO] Server started in stdout, got: %s", stdoutBuf.String())
	}
	if strings.Contains(stdoutBuf.String(), "[DEBUG]") {
		t.Errorf("unexpected debug logs when debug is off: %s", stdoutBuf.String())
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
	if !strings.Contains(out, "[DEBUG] [ACTION] User logged in") {
		t.Errorf("expected [DEBUG] [ACTION] User logged in in stdout, got: %s", out)
	}
	if !strings.Contains(out, "[DEBUG] [HTTP] POST /upload -> 200") {
		t.Errorf("expected [DEBUG] [HTTP] log in stdout, got: %s", out)
	}
}
