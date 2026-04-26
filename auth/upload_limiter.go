package auth

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	// AuthUploadMaxPerMinute caps authenticated upload-related requests per session.
	AuthUploadMaxPerMinute = 100
	// AuthUploadBurst allows short-lived bursts while preserving the sustained rate cap.
	AuthUploadBurst = 25
	// MaxConcurrentChunkUploads caps globally active chunk uploads to reduce I/O abuse.
	MaxConcurrentChunkUploads = 25
)

type sessionRateState struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type uploadLimiterStore struct {
	mu       sync.Mutex
	sessions map[string]*sessionRateState
}

var uploadLimiter = &uploadLimiterStore{
	sessions: make(map[string]*sessionRateState),
}

// AllowUploadRequest returns false when the authenticated session exceeds upload request rate.
func AllowUploadRequest(r *http.Request) bool {
	sessionID := GetSessionCookie(r)
	if sessionID == "" {
		Debugf("Upload request rejected: missing session cookie")
		return false
	}

	now := time.Now()
	uploadLimiter.mu.Lock()
	defer uploadLimiter.mu.Unlock()

	state, ok := uploadLimiter.sessions[sessionID]
	if !ok {
		state = &sessionRateState{
			limiter:  rate.NewLimiter(rate.Every(time.Minute/AuthUploadMaxPerMinute), AuthUploadBurst),
			lastSeen: now,
		}
		uploadLimiter.sessions[sessionID] = state
		Debugf("Created upload limiter for session")
	}

	state.lastSeen = now
	allowed := state.limiter.Allow()
	if !allowed {
		Debugf("Upload request rate-limited for session")
	}
	return allowed
}

// CleanupUploadLimiters removes stale limiter entries for inactive sessions.
func CleanupUploadLimiters() {
	cutoff := time.Now().Add(-20 * time.Minute)
	uploadLimiter.mu.Lock()
	defer uploadLimiter.mu.Unlock()
	removed := 0
	for sessionID, state := range uploadLimiter.sessions {
		if state.lastSeen.Before(cutoff) {
			delete(uploadLimiter.sessions, sessionID)
			removed++
		}
	}
	if removed > 0 {
		Debugf("Cleaned up %d stale upload limiter entries", removed)
	}
}

// StartUploadLimiterCleanupRoutine runs periodic cleanup for in-memory upload limiter state.
func StartUploadLimiterCleanupRoutine() {
	Debugf("Starting upload limiter cleanup routine")
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			CleanupUploadLimiters()
		}
	}()
}
