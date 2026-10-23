package logger

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

var (
	mu     sync.RWMutex
	debug  bool
	stdOut io.Writer = os.Stdout
	errOut io.Writer = os.Stderr
)

// Sanitize strips or escapes ASCII control characters (including CR, LF, and NUL) to prevent log injection
func Sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if unicode.IsControl(r) {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// sanitizeArgs escapes control characters in string arguments before formatting.
func sanitizeArgs(v []interface{}) []interface{} {
	if len(v) == 0 {
		return v
	}
	out := make([]interface{}, len(v))
	for i, arg := range v {
		switch val := arg.(type) {
		case string:
			out[i] = Sanitize(val)
		case error:
			if val != nil {
				out[i] = Sanitize(val.Error())
			} else {
				out[i] = val
			}
		default:
			out[i] = arg
		}
	}
	return out
}

// SetOutput redirects standard and error logs to custom writers (useful for testing).
func SetOutput(std, err io.Writer) {
	mu.Lock()
	defer mu.Unlock()
	if std == nil {
		std = os.Stdout
	}
	if err == nil {
		err = os.Stderr
	}
	stdOut = std
	errOut = err
}

// ResetOutput restores default standard and error logs to os.Stdout and os.Stderr.
func ResetOutput() {
	mu.Lock()
	defer mu.Unlock()
	stdOut = os.Stdout
	errOut = os.Stderr
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

func writeFormatted(isErr bool, tag string, msg string) {
	safeMsg := Sanitize(msg)

	mu.RLock()
	w := stdOut
	if isErr {
		w = errOut
	}
	mu.RUnlock()

	ts := time.Now().Format("2006/01/02 15:04:05")
	line := fmt.Sprintf("%s %s %s\n", ts, tag, safeMsg)

	mu.Lock()
	_, _ = w.Write([]byte(line))
	mu.Unlock()
}

// Info logs standard operational events (startup, shutdown, rate-limit lockouts).
func Info(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, sanitizeArgs(v)...)
	writeFormatted(false, "[INFO]", msg)
}

// Warn logs security warnings and suspicious events. Always printed.
func Warn(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, sanitizeArgs(v)...)
	writeFormatted(false, "[WARN]", msg)
}

// Error logs error messages. Always printed to backend console.
func Error(format string, v ...interface{}) {
	msg := fmt.Sprintf(format, sanitizeArgs(v)...)
	writeFormatted(true, "[ERROR]", msg)
}

// Debug logs detailed diagnostic information. Only printed when debug mode is enabled.
func Debug(format string, v ...interface{}) {
	if !IsDebug() {
		return
	}
	msg := fmt.Sprintf(format, sanitizeArgs(v)...)
	writeFormatted(false, "[DEBUG]", msg)
}

// Action logs user or administrative audit actions. Only printed when debug mode is enabled.
func Action(format string, v ...interface{}) {
	if !IsDebug() {
		return
	}
	msg := fmt.Sprintf(format, sanitizeArgs(v)...)
	writeFormatted(false, "[DEBUG] [AUDIT] [ACTION]", msg)
}

// Audit logs a structured security audit event at DEBUG level with explicit key-value attributes.
// Control characters in string attributes and the message are escaped automatically.
// Only printed when debug mode is enabled.
func Audit(event string, attrs ...slog.Attr) {
	if !IsDebug() {
		return
	}
	var summaryParts []string
	for _, a := range attrs {
		if a.Value.Kind() == slog.KindString {
			s := Sanitize(a.Value.String())
			summaryParts = append(summaryParts, fmt.Sprintf("%s=%s", a.Key, s))
		} else {
			summaryParts = append(summaryParts, fmt.Sprintf("%s=%v", a.Key, a.Value.Any()))
		}
	}
	msg := event
	if len(summaryParts) > 0 {
		msg = fmt.Sprintf("%s (%s)", event, strings.Join(summaryParts, ", "))
	}
	writeFormatted(false, "[DEBUG] [AUDIT] [ACTION]", msg)
}

// HTTP logs detailed HTTP request and response information. Only printed when debug mode is enabled.
func HTTP(method, path string, status int, duration time.Duration, remoteAddr, user string) {
	if !IsDebug() {
		return
	}
	safeMethod := Sanitize(method)
	safePath := Sanitize(path)
	safeRemote := Sanitize(remoteAddr)
	safeUser := Sanitize(user)
	durStr := duration.Round(time.Microsecond).String()
	var msg string
	if safeUser != "" {
		msg = fmt.Sprintf("%s %s -> %d (%s) from %s (user: %s)", safeMethod, safePath, status, durStr, safeRemote, safeUser)
	} else {
		msg = fmt.Sprintf("%s %s -> %d (%s) from %s", safeMethod, safePath, status, durStr, safeRemote)
	}
	writeFormatted(false, "[DEBUG] [HTTP]", msg)
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
