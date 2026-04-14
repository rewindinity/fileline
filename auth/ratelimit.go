package auth

import (
	"net/http"
	"sync"
	"time"
)

// IPBan tracks failed-auth state and temporary ban window for one client IP.
type IPBan struct {
	IP        string
	Attempts  int
	BannedAt  time.Time
	ExpiresAt time.Time
}

// RateLimiter holds in-memory anti-bruteforce counters keyed by client IP.
type RateLimiter struct {
	mu       sync.RWMutex
	attempts map[string]*IPBan
}

var limiter = &RateLimiter{
	attempts: make(map[string]*IPBan),
}

const (
	// MaxAttempts is the number of consecutive failures before a temporary ban is applied.
	MaxAttempts = 5
	// BanDuration is the ban window and also the expiry window for attempt counters.
	BanDuration = 1 * time.Hour
)

/**
  GetClientIP resolves the client IP from trusted proxy headers or RemoteAddr.
  @param r - The incoming HTTP request.
  @param isBehindProxy - Whether proxy-forwarded client IP headers are trusted.
  @returns string - The resulting string value.
*/
func GetClientIP(r *http.Request, isBehindProxy bool) string {
	// Only check reverse proxy headers if behind proxy
	if isBehindProxy {
		// Check X-Real-IP header first (most reliable for reverse proxies)
		if ip := r.Header.Get("X-Real-IP"); ip != "" {
			return ip
		}
		// Check X-Forwarded-For header (may contain multiple IPs)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP in the chain
			for i := 0; i < len(xff); i++ {
				if xff[i] == ',' {
					return xff[:i]
				}
			}
			return xff
		}
	}
	// Fall back to RemoteAddr, Remove port if present
	ip := r.RemoteAddr
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == ':' {
			return ip[:i]
		}
	}
	return ip
}

/**
  IsIPBanned reports whether the client IP is currently within an active ban window.
  @param r - The incoming HTTP request.
  @param isBehindProxy - Whether proxy-forwarded client IP headers are trusted.
  @returns bool - True when is ip banned is satisfied; otherwise false.
*/
func IsIPBanned(r *http.Request, isBehindProxy bool) bool {
	ip := GetClientIP(r, isBehindProxy)
	limiter.mu.RLock()
	defer limiter.mu.RUnlock()
	ban, exists := limiter.attempts[ip]
	if !exists {
		return false
	}
	// Check if ban has expired
	if time.Now().After(ban.ExpiresAt) {
		// Clean up expired ban (will be done in unlock)
		return false
	}
	return ban.Attempts >= MaxAttempts
}

/**
  RecordFailedAttempt increments failed-auth counters and applies a temporary ban.
  @param r - The incoming HTTP request.
  @param isBehindProxy - Whether proxy-forwarded client IP headers are trusted.
  @returns bool - True when record failed attempt is satisfied; otherwise false.
*/
func RecordFailedAttempt(r *http.Request, isBehindProxy bool) bool {
	ip := GetClientIP(r, isBehindProxy)
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := time.Now()
	ban, exists := limiter.attempts[ip]
	if !exists {
		limiter.attempts[ip] = &IPBan{
			IP:        ip,
			Attempts:  1,
			ExpiresAt: now.Add(BanDuration), // Set expiry for first attempt
		}
		return false
	}
	// Reset if ban has expired
	if !ban.ExpiresAt.IsZero() && now.After(ban.ExpiresAt) {
		limiter.attempts[ip] = &IPBan{
			IP:        ip,
			Attempts:  1,
			ExpiresAt: now.Add(BanDuration),
		}
		return false
	}
	// Increment attempts
	ban.Attempts++
	// Ban if threshold reached
	if ban.Attempts >= MaxAttempts {
		ban.BannedAt = now
		ban.ExpiresAt = now.Add(BanDuration)
		return true
	}

	return false
}

/**
  ResetAttempts clears in-memory failure state for the caller IP.
  @param r - The incoming HTTP request.
  @param isBehindProxy - Whether proxy-forwarded client IP headers are trusted.
  @returns void
*/
func ResetAttempts(r *http.Request, isBehindProxy bool) {
	ip := GetClientIP(r, isBehindProxy)
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	delete(limiter.attempts, ip)
}

/**
  CleanupExpiredBans prunes expired entries to keep memory bounded.
  @param none - This function does not accept parameters.
  @returns void
*/
func CleanupExpiredBans() {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	now := time.Now()
	for ip, ban := range limiter.attempts {
		if now.After(ban.ExpiresAt) {
			delete(limiter.attempts, ip)
		}
	}
}

/**
  StartCleanupRoutine starts periodic cleanup for expired ban entries.
  @param none - This function does not accept parameters.
  @returns void
*/
func StartCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			CleanupExpiredBans()
		}
	}()
}
