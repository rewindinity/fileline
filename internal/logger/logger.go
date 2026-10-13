package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

var (
	mu     sync.RWMutex
	debug  bool
	stdLog = log.New(os.Stdout, "", log.LstdFlags)
	errLog = log.New(os.Stderr, "", log.LstdFlags)
)

// SetOutput redirects standard and error logs to custom writers (useful for testing).
func SetOutput(std, err io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	stdLog = log.New(std, "", log.LstdFlags)
	errLog = log.New(err, "", log.LstdFlags)
}

// ResetOutput restores default standard and error logs to os.Stdout and os.Stderr.
func ResetOutput() {
	mu.Lock()
	defer mu.Unlock()
	stdLog = log.New(os.Stdout, "", log.LstdFlags)
	errLog = log.New(os.Stderr, "", log.LstdFlags)
}

// SetDebug enables or disables debug logging mode.
func SetDebug(enabled bool) {
	mu.Lock()
	defer mu.Unlock()
	debug = enabled
}

// IsDebug returns whether debug logging mode is enabled.
func IsDebug() bool {
	mu.RLock()
	defer mu.RUnlock()
	return debug
}

// Info logs standard operational events (startup, shutdown).
func Info(format string, v ...interface{}) {
	stdLog.Printf("[INFO] "+format, v...)
}

// Error logs error messages. Always printed to backend console.
func Error(format string, v ...interface{}) {
	errLog.Printf("[ERROR] "+format, v...)
}

// Debug logs detailed diagnostic information. Only printed when debug mode is enabled.
func Debug(format string, v ...interface{}) {
	if !IsDebug() {
		return
	}
	stdLog.Printf("[DEBUG] "+format, v...)
}

// Action logs user or administrative actions. Only printed when debug mode is enabled.
func Action(format string, v ...interface{}) {
	if !IsDebug() {
		return
	}
	stdLog.Printf("[DEBUG] [ACTION] "+format, v...)
}

// HTTP logs detailed HTTP request and response information. Only printed when debug mode is enabled.
func HTTP(method, path string, status int, duration time.Duration, remoteAddr, user string) {
	if !IsDebug() {
		return
	}
	durStr := duration.Round(time.Microsecond).String()
	if user != "" {
		stdLog.Printf("[DEBUG] [HTTP] %s %s -> %d (%s) from %s (user: %s)", method, path, status, durStr, remoteAddr, user)
	} else {
		stdLog.Printf("[DEBUG] [HTTP] %s %s -> %d (%s) from %s", method, path, status, durStr, remoteAddr)
	}
}

// FormatBytes formats byte count into a human-readable string (e.g. 1.2 MB).
func FormatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
