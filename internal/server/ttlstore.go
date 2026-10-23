package server

import (
	"sync"
	"time"
)

const (
	defaultTTLStoreMaxEntries = 10000
	defaultTTLStoreDuration   = 10 * time.Minute
	webAuthnSessionTTL        = 5 * time.Minute
	totpSetupSessionTTL       = 10 * time.Minute
	recoveryDisplayTTL        = 30 * time.Minute
)

type ttlEntry[V any] struct {
	val V
	exp time.Time
}

// ttlStore is a concurrency-safe, bounded in-memory key-value store with per-entry TTL expiration and oldest-first eviction when the capacity cap is reached
type ttlStore[K comparable, V any] struct {
	mu       sync.Mutex
	m        map[K]ttlEntry[V]
	ttl      time.Duration
	max      int
	initOnce sync.Once
}

func newTTLStore[K comparable, V any](ttl time.Duration, max int) ttlStore[K, V] {
	if ttl <= 0 {
		ttl = defaultTTLStoreDuration
	}
	if max <= 0 {
		max = defaultTTLStoreMaxEntries
	}
	return ttlStore[K, V]{
		m:   make(map[K]ttlEntry[V]),
		ttl: ttl,
		max: max,
	}
}

func (s *ttlStore[K, V]) ensureInitLocked() {
	if s.m == nil {
		s.m = make(map[K]ttlEntry[V])
	}
	if s.ttl <= 0 {
		s.ttl = defaultTTLStoreDuration
	}
	if s.max <= 0 {
		s.max = defaultTTLStoreMaxEntries
	}
}

// Store inserts or updates key with value, setting its expiration to time.Now().Add(ttl).
// If the store is at capacity, expired entries are swept first, and if still full, the oldest entry is evicted.
func (s *ttlStore[K, V]) Store(key K, val V) {
	s.StoreAt(key, val, time.Now())
}

// StoreAt inserts or updates key with value using the provided current timestamp now.
func (s *ttlStore[K, V]) StoreAt(key K, val V, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureInitLocked()

	if _, exists := s.m[key]; !exists && len(s.m) >= s.max {
		s.evictLocked(now)
	}
	s.m[key] = ttlEntry[V]{
		val: val,
		exp: now.Add(s.ttl),
	}
}

// Load retrieves the value for key if it exists and has not expired. Expiired entries are lazily deleted on access.
func (s *ttlStore[K, V]) Load(key K) (V, bool) {
	return s.LoadAt(key, time.Now())
}

// LoadAt retrieves the value for key if it exists and has not expired at now
func (s *ttlStore[K, V]) LoadAt(key K, now time.Time) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureInitLocked()

	entry, ok := s.m[key]
	if !ok {
		var zero V
		return zero, false
	}
	if !now.Before(entry.exp) {
		delete(s.m, key)
		var zero V
		return zero, false
	}
	return entry.val, true
}

// LoadAndDelete retrieves and removes the value for key if it exists and has not expired
func (s *ttlStore[K, V]) LoadAndDelete(key K) (V, bool) {
	return s.LoadAndDeleteAt(key, time.Now())
}

// LoadAndDeleteAt retrieves and removes the value for key if it exists and has not expired at now
func (s *ttlStore[K, V]) LoadAndDeleteAt(key K, now time.Time) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureInitLocked()

	entry, ok := s.m[key]
	if !ok {
		var zero V
		return zero, false
	}
	delete(s.m, key)
	if !now.Before(entry.exp) {
		var zero V
		return zero, false
	}
	return entry.val, true
}

// Delete removes key from the store
func (s *ttlStore[K, V]) Delete(key K) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m != nil {
		delete(s.m, key)
	}
}

// Len returns the current number of entries in the store
func (s *ttlStore[K, V]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// Sweep removes all entries that have expired at now
func (s *ttlStore[K, V]) Sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.m) == 0 {
		return
	}
	for k, e := range s.m {
		if !now.Before(e.exp) {
			delete(s.m, k)
		}
	}
}

func (s *ttlStore[K, V]) evictLocked(now time.Time) {
	var oldestKey K
	var oldestExp time.Time
	hasOldest := false

	for k, e := range s.m {
		if !now.Before(e.exp) {
			delete(s.m, k)
			continue
		}
		if !hasOldest || e.exp.Before(oldestExp) {
			oldestKey = k
			oldestExp = e.exp
			hasOldest = true
		}
	}
	if len(s.m) >= s.max && hasOldest {
		delete(s.m, oldestKey)
	}
}
