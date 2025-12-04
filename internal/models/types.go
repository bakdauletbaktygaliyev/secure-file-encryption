package models

import "time"

// EncryptedFile represents an encrypted file with all necessary metadata
type EncryptedFile struct {
	Version          string    `json:"version"`
	EncryptedData    []byte    `json:"encrypted_data"`
	EncryptedKey     []byte    `json:"encrypted_key"`
	Nonce            []byte    `json:"nonce"`
	Salt             []byte    `json:"salt"`
	Hash             []byte    `json:"hash"`
	Signature        []byte    `json:"signature"`
	OriginalName     string    `json:"original_name"`
	OriginalSize     int64     `json:"original_size"`
	Timestamp        time.Time `json:"timestamp"`
	KDFIterations    int       `json:"kdf_iterations"`
	EncryptionMethod string    `json:"encryption_method"`
}

// KeyPair represents an RSA key pair
type KeyPair struct {
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
}

// EncryptionConfig holds encryption parameters
type EncryptionConfig struct {
	Algorithm     string
	KeySize       int
	KDFIterations int
	UseRSA        bool
}

// DefaultConfig returns secure default configuration
func DefaultConfig() *EncryptionConfig {
	return &EncryptionConfig{
		Algorithm:     "AES-256-GCM",
		KeySize:       32, // 256 bits
		KDFIterations: 100000,
		UseRSA:        true,
	}
}
