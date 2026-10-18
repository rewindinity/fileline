package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"

	"fileline/internal/translations"
)

const (
	minPasswordLength = 8
	maxPasswordLength = 72 // bcrypt maximum input length
	minUsernameLength = 3
	maxUsernameLength = 32
	maxURLPathLength  = 128
	maxCustomNameLen  = 255
)

var allowedThemes = map[string]struct{}{
	"dark-blue":    {},
	"dark-green":   {},
	"dark-red":     {},
	"dark-orange":  {},
	"dark-purple":  {},
	"oled":         {},
	"light-blue":   {},
	"light-green":  {},
	"light-red":    {},
	"light-orange": {},
	"light-purple": {},
	"dark":         {},
	"light":        {},
}

var commonBreachedPasswords = map[string]struct{}{
	"password":    {},
	"password123": {},
	"12345678":    {},
	"123456789":   {},
	"1234567890":  {},
	"qwerty123":   {},
	"qwertyuiop":  {},
	"admin123":    {},
	"letmein123":  {},
	"welcome123":  {},
	"iloveyou":    {},
	"changeme":    {},
	"passw0rd":    {},
}

// validatePassword enforces password length and common breached-password checks
func validatePassword(pw string) error {
	if len(pw) < minPasswordLength {
		return errors.New("Password must be at least 8 characters")
	}
	if len(pw) > maxPasswordLength {
		return errors.New("Password must not exceed 72 characters")
	}
	if _, breached := commonBreachedPasswords[strings.ToLower(strings.TrimSpace(pw))]; breached {
		return errors.New("Password is too common")
	}
	return nil
}

// validateUsername enforces a strict character set and length for usernames
func validateUsername(username string) error {
	if len(username) < minUsernameLength || len(username) > maxUsernameLength {
		return errors.New("Username must be 3-32 characters")
	}
	for i := 0; i < len(username); i++ {
		c := username[i]
		ok := (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '_' || c == '.' || c == '-'
		if !ok {
			return errors.New("Username contains invalid characters")
		}
	}
	return nil
}

// isAllowedURLPathChar reports whether b is in [A-Za-z0-9._~-].
func isAllowedURLPathChar(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '.' || b == '_' || b == '~' || b == '-'
}

// validateURLPath verifies that an explicit url_path matches
func validateURLPath(p string) error {
	if len(p) == 0 || len(p) > maxURLPathLength {
		return errors.New("Invalid URL path length")
	}
	if p == "." || p == ".." {
		return errors.New("Invalid URL path")
	}
	for i := 0; i < len(p); i++ {
		if !isAllowedURLPathChar(p[i]) {
			return errors.New("Invalid URL path characters")
		}
	}
	return nil
}

// slugifyURLPath converts an arbitrary filename or custom title into a valid url_path matching ^[A-Za-z0-9._~-]{1,128}$.
func slugifyURLPath(input string) string {
	var sb strings.Builder
	lastHyphen := false
	for i := 0; i < len(input) && sb.Len() < maxURLPathLength; i++ {
		c := input[i]
		if isAllowedURLPathChar(c) {
			sb.WriteByte(c)
			lastHyphen = (c == '-')
		} else if c == ' ' || c == '/' || c == '\\' || c == ':' {
			if sb.Len() > 0 && !lastHyphen {
				sb.WriteByte('-')
				lastHyphen = true
			}
		}
	}
	res := strings.Trim(sb.String(), "-.")
	if res == "" || res == "." || res == ".." {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		return "file-" + hex.EncodeToString(b)
	}
	if len(res) > maxURLPathLength {
		res = res[:maxURLPathLength]
	}
	return res
}

// appendRandomURLPathSuffix appends a short random suffix before any file extension to resolve collisions.
func appendRandomURLPathSuffix(base string) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	suffix := "-" + hex.EncodeToString(b)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	maxStem := maxURLPathLength - len(suffix) - len(ext)
	if maxStem < 1 {
		if len(base) > maxURLPathLength-len(suffix) {
			base = base[:maxURLPathLength-len(suffix)]
		}
		return base + suffix
	}
	if len(stem) > maxStem {
		stem = stem[:maxStem]
	}
	return stem + suffix + ext
}

// isValidHexColor checks whether s matches
func isValidHexColor(s string) bool {
	if len(s) != 7 || s[0] != '#' {
		return false
	}
	for i := 1; i < 7; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isValidTheme checks membership in the known theme set (allowing "global" when allowGlobal is true).
func isValidTheme(theme string, allowGlobal bool) bool {
	if allowGlobal && theme == "global" {
		return true
	}
	_, ok := allowedThemes[theme]
	return ok
}

// isValidLanguage checks membership in known language codes (allowing "global" when allowGlobal is true).
func isValidLanguage(lang string, allowGlobal bool) bool {
	if allowGlobal && lang == "global" {
		return true
	}
	_, ok := translations.LanguageNames[lang]
	return ok
}

// isUniqueConstraintError detects SQLite and PostgreSQL unique constraint violations.
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "unique violation")
}

// validateDriveID checks that driveID is either empty/"default" or refers to an enabled drive in s.cfg.Drives.
func (s *Server) validateDriveID(driveID string) bool {
	if driveID == "" || driveID == "default" {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg == nil {
		return false
	}
	for _, d := range s.cfg.Drives {
		if d.ID == driveID && d.Enabled {
			return true
		}
	}
	return false
}
