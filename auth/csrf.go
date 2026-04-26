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
		Debugf("CSRF validation failed: missing session cookie")
		return false
	}

	token := strings.TrimSpace(r.FormValue("csrf_token"))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	}
	if token == "" {
		Debugf("CSRF validation failed: missing token on path=%s", r.URL.Path)
		return false
	}

	expected := csrfTokenForSession(sessionID)
	if len(token) != len(expected) {
		Debugf("CSRF validation failed: token length mismatch on path=%s", r.URL.Path)
		return false
	}
	valid := subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
	if !valid {
		Debugf("CSRF validation failed: token mismatch on path=%s", r.URL.Path)
	}
	return valid
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
	tokenValid := ValidateCSRFToken(r)
	originValid := ValidateSameOrigin(r, isBehindProxy)
	if !tokenValid || !originValid {
		Debugf("CSRF request rejected on path=%s (token_valid=%t same_origin=%t)", r.URL.Path, tokenValid, originValid)
	}
	return tokenValid && originValid
}
