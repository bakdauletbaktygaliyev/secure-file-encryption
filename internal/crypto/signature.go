package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// Signer handles digital signature operations using ECDSA
type Signer struct{}

// NewSigner creates a new signer
func NewSigner() *Signer {
	return &Signer{}
}

// GenerateSigningKey generates an ECDSA key pair for signing
func (s *Signer) GenerateSigningKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	return privateKey, nil
}

// Sign creates a digital signature for data
func (s *Signer) Sign(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)

	r, sig, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	signature, err := encodeSignature(r, sig)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signature: %w", err)
	}

	return signature, nil
}

// Verify verifies a digital signature
func (s *Signer) Verify(data []byte, signature []byte, publicKey *ecdsa.PublicKey) error {
	hash := sha256.Sum256(data)

	r, sig, err := decodeSignature(signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if !ecdsa.Verify(publicKey, hash[:], r, sig) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// ExportSigningKey exports ECDSA private key to PEM format
func (s *Signer) ExportSigningKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	return keyPEM, nil
}

// ExportVerifyingKey exports ECDSA public key to PEM format
func (s *Signer) ExportVerifyingKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	})

	return keyPEM, nil
}

// ImportSigningKey imports ECDSA private key from PEM format
func (s *Signer) ImportSigningKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}

	return privateKey, nil
}

// ImportVerifyingKey imports ECDSA public key from PEM format
func (s *Signer) ImportVerifyingKey(keyPEM []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPub, nil
}

func encodeSignature(r, s *big.Int) ([]byte, error) {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	signature := make([]byte, 64)
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):], sBytes)

	return signature, nil
}

func decodeSignature(signature []byte) (*big.Int, *big.Int, error) {
	if len(signature) != 64 {
		return nil, nil, fmt.Errorf("invalid signature length")
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])

	return r, s, nil
}
