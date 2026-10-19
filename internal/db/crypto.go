package db

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

const totpEncryptedPrefix = "enc:v1:"

var (
	configuredDataKeyMu sync.RWMutex
	configuredDataKey   string
	fallbackDataKeyOnce sync.Once
	fallbackDataKey     [32]byte
)

// SetDataKey sets the in-memory data encryption key loaded from configuration.
func SetDataKey(k string) {
	configuredDataKeyMu.Lock()
	defer configuredDataKeyMu.Unlock()
	configuredDataKey = strings.TrimSpace(k)
}

func resolveDataKey() ([32]byte, error) {
	raw := strings.TrimSpace(os.Getenv("FL_DATA_KEY"))
	if raw == "" {
		configuredDataKeyMu.RLock()
		raw = configuredDataKey
		configuredDataKeyMu.RUnlock()
	}
	if raw != "" {
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
			var k [32]byte
			copy(k[:], decoded)
			return k, nil
		}
		if decoded, err := base64.RawURLEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
			var k [32]byte
			copy(k[:], decoded)
			return k, nil
		}
		if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
			var k [32]byte
			copy(k[:], decoded)
			return k, nil
		}
		return sha256.Sum256([]byte("fileline-totp-key-v1:" + raw)), nil
	}

	fallbackDataKeyOnce.Do(func() {
		keyPath := "data/data.key"
		if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
			copy(fallbackDataKey[:], data)
			return
		}
		if _, err := io.ReadFull(rand.Reader, fallbackDataKey[:]); err == nil {
			_ = os.MkdirAll("data", 0o750)
			_ = os.WriteFile(keyPath, fallbackDataKey[:], 0o600)
		}
	})
	return fallbackDataKey, nil
}

// EncryptTOTPSecret encrypts a plaintext TOTP secret using AES-256-GCM.
func EncryptTOTPSecret(plaintext string) (string, error) {
	if plaintext == "" || strings.HasPrefix(plaintext, totpEncryptedPrefix) {
		return plaintext, nil
	}
	key, err := resolveDataKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return totpEncryptedPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// DecryptTOTPSecret decrypts an AES-256-GCM encrypted TOTP secret.
// Unprefixed legacy plaintext values are returned as-is for backwards compatibility.
func DecryptTOTPSecret(stored string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, totpEncryptedPrefix) {
		return stored, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, totpEncryptedPrefix))
	if err != nil {
		return "", fmt.Errorf("invalid encrypted TOTP secret encoding: %w", err)
	}
	key, err := resolveDataKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", fmt.Errorf("encrypted TOTP secret too short")
	}
	plaintext, err := gcm.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt TOTP secret: %w", err)
	}
	return string(plaintext), nil
}
