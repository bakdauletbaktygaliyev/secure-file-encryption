package crypto

import (
	"crypto/sha256"
	"fmt"
)

// Hasher handles cryptographic hashing operations
type Hasher struct{}

// NewHasher creates a new hasher
func NewHasher() *Hasher {
	return &Hasher{}
}

// Hash computes SHA-256 hash of data
func (h *Hasher) Hash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// VerifyHash verifies if data matches the given hash
func (h *Hasher) VerifyHash(data []byte, expectedHash []byte) error {
	actualHash := h.Hash(data)

	if len(actualHash) != len(expectedHash) {
		return fmt.Errorf("hash length mismatch")
	}

	var diff byte
	for i := 0; i < len(actualHash); i++ {
		diff |= actualHash[i] ^ expectedHash[i]
	}

	if diff != 0 {
		return fmt.Errorf("hash verification failed: data has been modified")
	}

	return nil
}

// HashFile computes SHA-256 hash suitable for file integrity
func (h *Hasher) HashFile(fileData []byte) ([]byte, error) {
	if len(fileData) == 0 {
		return nil, fmt.Errorf("cannot hash empty file")
	}
	return h.Hash(fileData), nil
}
