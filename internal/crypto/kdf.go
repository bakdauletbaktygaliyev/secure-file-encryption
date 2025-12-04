package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// KDF handles key derivation operations
type KDF struct{}

// NewKDF creates a new KDF instance
func NewKDF() *KDF {
	return &KDF{}
}

// DeriveKey derives a cryptographic key from a password using PBKDF2
// Returns: derived key, salt, error
func (k *KDF) DeriveKey(password string, salt []byte, iterations int, keyLen int) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32) // 256-bit salt
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	if iterations < 10000 {
		return nil, nil, fmt.Errorf("iterations too low (minimum 10000)")
	}
	if keyLen < 16 {
		return nil, nil, fmt.Errorf("key length too short (minimum 16 bytes)")
	}

	key := pbkdf2.Key([]byte(password), salt, iterations, keyLen, sha256.New)

	return key, salt, nil
}

// GenerateSalt generates a random salt
func (k *KDF) GenerateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
