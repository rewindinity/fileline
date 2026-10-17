package server

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	loginMaxAttempts      = 10
	loginWindow           = 15 * time.Minute
	resetMaxAttempts      = 3
	resetLockoutDuration  = time.Hour
	twoFAMaxAttempts      = 5
	twoFASessionTTL       = 5 * time.Minute
	maxRateLimiterEntries = 10000
)

var (
	dummyHashOnce     sync.Once
	dummyPasswordHash []byte
)

// getDummyPasswordHash returns a valid bcrypt hash computed once at DefaultCost so login attempts for non-existent users run in uniform time
func getDummyPasswordHash() []byte {
	dummyHashOnce.Do(func() {
		h, err := bcrypt.GenerateFromPassword([]byte("fileline-dummy-password-for-timing-uniformity"), bcrypt.DefaultCost)
		if err == nil {
			dummyPasswordHash = h
		}
	})
	return dummyPasswordHash
}

// twoFASession represents an in-flight 2FA challenge with server-enforced TTL and attempt limit
type twoFASession struct {
	Username  string
	ExpiresAt time.Time
	Attempts  int
}

type authBucket struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
}

// authRateLimiter tracks authentication failures per key (such as IP or IP+username)
type authRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*authBucket
}

func newAuthRateLimiter() *authRateLimiter {
	return &authRateLimiter{
		buckets: make(map[string]*authBucket),
	}
}

func (l *authRateLimiter) check(key string, now time.Time) (blocked bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		return false, 0
	}
	if !b.blockedUntil.IsZero() {
		if now.Before(b.blockedUntil) {
			return true, b.blockedUntil.Sub(now)
		}
		delete(l.buckets, key)
		return false, 0
	}
	return false, 0
}

func (l *authRateLimiter) recordFailure(key string, now time.Time, maxAttempts int, window, baseLockout time.Duration) (attempts int, blocked bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.buckets) >= maxRateLimiterEntries {
		l.evictExpiredLocked(now)
	}

	b, ok := l.buckets[key]
	if !ok || (!b.blockedUntil.IsZero() && !now.Before(b.blockedUntil)) || (b.blockedUntil.IsZero() && now.Sub(b.windowStart) > window) {
		b = &authBucket{
			windowStart: now,
		}
		l.buckets[key] = b
	}

	b.failures++
	attempts = b.failures
	if b.failures >= maxAttempts {
		// Exponential backoff for repeated overflows within the window
		shift := b.failures - maxAttempts
		if shift > 4 {
			shift = 4
		}
		lockDur := baseLockout * time.Duration(1<<shift)
		if lockDur > 24*time.Hour {
			lockDur = 24 * time.Hour
		}
		b.blockedUntil = now.Add(lockDur)
		return attempts, true, lockDur
	}
	return attempts, false, 0
}

func (l *authRateLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

func (l *authRateLimiter) evictExpiredLocked(now time.Time) {
	var oldestKey string
	var oldestTime time.Time
	for k, b := range l.buckets {
		if !b.blockedUntil.IsZero() && now.After(b.blockedUntil) {
			delete(l.buckets, k)
			continue
		}
		if b.blockedUntil.IsZero() && now.Sub(b.windowStart) > loginWindow {
			delete(l.buckets, k)
			continue
		}
		if oldestKey == "" || b.windowStart.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.windowStart
		}
	}
	if len(l.buckets) >= maxRateLimiterEntries && oldestKey != "" {
		delete(l.buckets, oldestKey)
	}
}

func normalizeIP(addr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(addr)
}

func authRateKey(scope, ip, username string) string {
	return fmt.Sprintf("%s|%s|%s", scope, normalizeIP(ip), strings.ToLower(strings.TrimSpace(username)))
}

func setRetryAfterHeader(w http.ResponseWriter, d time.Duration) {
	secs := int(d.Seconds())
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
}

// matchTOTPStep validates code against secret at now (with +1 30s skew) and returns the matched time-step
func matchTOTPStep(code, secret string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != 6 || secret == "" {
		return 0, false
	}
	baseStep := now.UTC().Unix() / 30
	// Check [baseStep-1, baseStep, baseStep+1]
	for _, offset := range []int64{0, -1, 1} {
		step := baseStep + offset
		stepTime := time.Unix(step*30, 0).UTC()
		ok, err := totp.ValidateCustom(code, secret, stepTime, totp.ValidateOpts{
			Period:    30,
			Skew:      0,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err == nil && ok {
			return step, true
		}
	}
	return 0, false
}
