package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var csrfSecret []byte

func init() {
	csrfSecret = make([]byte, 32)
	if _, err := rand.Read(csrfSecret); err != nil {
		panic("failed to initialize CSRF secret: " + err.Error())
	}
}

func normalizeRequestHost(raw string) string {
	host := strings.TrimSpace(strings.Split(raw, ",")[0])
	if host == "" {
		return ""
	}

	if strings.Contains(host, "://") {
		if parsed, err := url.Parse(host); err == nil && parsed.Host != "" {
			host = parsed.Host
		}
	}

	host = strings.TrimSpace(strings.Split(host, "/")[0])
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func csrfTokenForSession(sessionID string) string {
	mac := hmac.New(sha256.New, csrfSecret)
	mac.Write([]byte(sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// CSRFToken returns the expected anti-CSRF token for the current authenticated session.
func CSRFToken(r *http.Request) string {
	sessionID := GetSessionCookie(r)
	if sessionID == "" {
		return ""
	}
	return csrfTokenForSession(sessionID)
}

// ValidateCSRFToken verifies that request-provided CSRF token matches the current session.
func ValidateCSRFToken(r *http.Request) bool {
	sessionID := GetSessionCookie(r)
	if sessionID == "" {
		return false
	}

	token := strings.TrimSpace(r.FormValue("csrf_token"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	}
	if token == "" {
		return false
	}

	expected := csrfTokenForSession(sessionID)
	if len(token) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

// ValidateSameOrigin checks Origin/Referer host against request host as secondary CSRF defense.
func ValidateSameOrigin(r *http.Request, isBehindProxy bool) bool {
	requestHost := normalizeRequestHost(r.Host)
	if isBehindProxy {
		if forwardedHost := normalizeRequestHost(r.Header.Get("X-Forwarded-Host")); forwardedHost != "" {
			requestHost = forwardedHost
		}
	}
	if requestHost == "" {
		return false
	}

	matchesHost := func(raw string) bool {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return false
		}
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Host == "" {
			return false
		}
		return normalizeRequestHost(parsed.Host) == requestHost
	}

	origin := r.Header.Get("Origin")
	if origin != "" {
		return matchesHost(origin)
	}

	referer := r.Header.Get("Referer")
	if referer != "" {
		return matchesHost(referer)
	}

	return false
}

// ValidateCSRFRequest enforces both token validation and same-origin verification.
func ValidateCSRFRequest(r *http.Request, isBehindProxy bool) bool {
	return ValidateCSRFToken(r) && ValidateSameOrigin(r, isBehindProxy)
}
