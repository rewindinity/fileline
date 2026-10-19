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
	fallbackDataKeyOnce sync.Once
	fallbackDataKey     [32]byte
)

// resolveDataKey returns a 32-byte AES-256 key derived from FL_DATA_KEY when set,
// or a process-local random 256-bit key when FL_DATA_KEY is not configured.
func resolveDataKey() [32]byte {
	raw := strings.TrimSpace(os.Getenv("FL_DATA_KEY"))
	if raw != "" {
		if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
			var k [32]byte
			copy(k[:], decoded)
			return k
		}
		if decoded, err := base64.RawURLEncoding.DecodeString(raw); err == nil && len(decoded) == 32 {
			var k [32]byte
			copy(k[:], decoded)
			return k
		}
		if decoded, err := hex.DecodeString(raw); err == nil && len(decoded) == 32 {
			var k [32]byte
			copy(k[:], decoded)
			return k
		}
		return sha256.Sum256([]byte("fileline-totp-key-v1:" + raw))
	}
	fallbackDataKeyOnce.Do(func() {
		_, _ = io.ReadFull(rand.Reader, fallbackDataKey[:])
	})
	return fallbackDataKey
}

// EncryptTOTPSecret encrypts a plaintext TOTP secret using AES-256-GCM.
func EncryptTOTPSecret(plaintext string) (string, error) {
	if plaintext == "" || strings.HasPrefix(plaintext, totpEncryptedPrefix) {
		return plaintext, nil
	}
	key := resolveDataKey()
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
	key := resolveDataKey()
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
