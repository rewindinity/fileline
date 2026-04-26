package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"

	"fileline/database"
	"fileline/models"
)

// SessionStore owns in-memory session lifecycle for the current process.
type SessionStore struct {
	sessions map[string]models.SessionData
	mu       sync.RWMutex
}

// Store is the process-local in-memory session store used by all handlers.
var Store = &SessionStore{sessions: make(map[string]models.SessionData)}

/**
  generateSessionID returns a cryptographically random token for session identity.
  @param none - This function does not accept parameters.
  @returns string - The identifier string.
*/
func generateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

/**
  Create inserts a fresh session record and returns its identifier.
  @param username - The username to authenticate.
  @param needs2FA - Whether the session requires two-factor verification.
  @returns string - The resulting string value.
*/
func (s *SessionStore) Create(username string, needs2FA bool) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := generateSessionID()
	s.sessions[id] = models.SessionData{
		Expiry:   time.Now().Add(24 * time.Hour),
		Needs2FA: needs2FA,
		Username: username,
	}
	Debugf("Session created for user=%q (needs_2fa=%t)", username, needs2FA)
	return id
}

/**
  Valid reports whether a session exists, is not expired, and has completed 2FA.
  @param id - The identifier to process.
  @returns bool - True when the session is active and fully authenticated; otherwise false.
*/
func (s *SessionStore) Valid(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, exists := s.sessions[id]
	if !exists {
		return false
	}
	if time.Now().After(data.Expiry) {
		delete(s.sessions, id)
		Debugf("Session expired for user=%q", data.Username)
		return false
	}
	return !data.Needs2FA
}

/**
  Needs2FA reports whether the session is in an intermediate post-password state.
  @param id - The identifier to process.
  @returns bool - True when the session exists and still requires 2FA verification; otherwise false.
*/
func (s *SessionStore) Needs2FA(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, exists := s.sessions[id]
	if !exists {
		return false
	}
	return data.Needs2FA
}

/**
  Complete2FA upgrades a session from pending 2FA to fully authenticated.
  @param id - The identifier to process.
  @returns void
*/
func (s *SessionStore) Complete2FA(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if data, exists := s.sessions[id]; exists {
		data.Needs2FA = false
		s.sessions[id] = data
		Debugf("Session 2FA completed for user=%q", data.Username)
	}
}

/**
  Delete removes a session from the in-memory store.
  @param id - The identifier to process.
  @returns void
*/
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if data, exists := s.sessions[id]; exists {
		Debugf("Session deleted for user=%q", data.Username)
	}
	delete(s.sessions, id)
}

/**
  IsLoggedIn validates the session cookie against the session store.
  @param r - The incoming HTTP request.
  @returns bool - True when the request carries a valid authenticated session; otherwise false.
*/
func IsLoggedIn(r *http.Request) bool {
	cookie, err := r.Cookie(models.SessionName)
	if err != nil {
		return false
	}
	return Store.Valid(cookie.Value)
}

/**
  RequireSetup redirects to setup until first-run configuration is complete.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns bool - True when the function handled the response and request processing should stop; otherwise false.
*/
func RequireSetup(w http.ResponseWriter, r *http.Request) bool {
	if !database.IsConfigured() {
		if database.HasConnectionError() {
			Debugf("RequireSetup blocked due to database connection error on path=%s", r.URL.Path)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return true
		}
		Debugf("RequireSetup redirect to /setup from path=%s", r.URL.Path)
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return true
	}
	return false
}

/**
  RequireAuth enforces authenticated access for protected pages.
  @param w - The HTTP response writer.
  @param r - The incoming HTTP request.
  @returns bool - True when the function handled the response and request processing should stop; otherwise false.
*/
func RequireAuth(w http.ResponseWriter, r *http.Request) bool {
	if !IsLoggedIn(r) {
		Debugf("RequireAuth redirect to /login from path=%s", r.URL.Path)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return true
	}
	return false
}

/**
  GetSessionCookie extracts the raw session ID from request cookies.
  @param r - The incoming HTTP request.
  @returns string - The session cookie value.
*/
func GetSessionCookie(r *http.Request) string {
	cookie, err := r.Cookie(models.SessionName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

/**
  SetSessionCookie persists the session ID in an HTTP-only cookie.
  @param w - The HTTP response writer.
  @param sessionID - The session identifier.
  @returns void
*/
func SetSessionCookie(w http.ResponseWriter, sessionID string) {
	Debugf("Setting session cookie (secure=%t)", database.Config.SSLEnabled)
	// Keep cookie scope minimal and HTTP-only to reduce accidental exposure.
	http.SetCookie(w, &http.Cookie{
		Name:     models.SessionName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   database.Config.SSLEnabled,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 hours
	})
}

/**
  ClearSessionCookie invalidates the browser cookie for the current session.
  @param w - The HTTP response writer.
  @returns void
*/
func ClearSessionCookie(w http.ResponseWriter) {
	Debugf("Clearing session cookie")
	http.SetCookie(w, &http.Cookie{
		Name:     models.SessionName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   database.Config.SSLEnabled,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}
