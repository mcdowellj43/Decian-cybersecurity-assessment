package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateKey generates a cryptographically secure random key
func GenerateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}

// GenerateBase64Key generates a base64-encoded random key
func GenerateBase64Key(length int) (string, error) {
	key, err := GenerateKey(length)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// HashSHA256 computes SHA256 hash of data
func HashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// HashSHA256Base64 computes SHA256 hash and returns base64-encoded result
func HashSHA256Base64(data []byte) string {
	hash := HashSHA256(data)
	return base64.StdEncoding.EncodeToString(hash)
}

// SecureCompare performs constant-time comparison of two byte slices
func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}

// ZeroBytes securely clears a byte slice
func ZeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}