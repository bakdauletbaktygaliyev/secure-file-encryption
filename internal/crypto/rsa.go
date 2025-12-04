package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// RSAEncryptor handles RSA encryption operations
type RSAEncryptor struct{}

// NewRSAEncryptor creates a new RSA encryptor
func NewRSAEncryptor() *RSAEncryptor {
	return &RSAEncryptor{}
}

// GenerateKeyPair generates a 2048-bit RSA key pair
func (r *RSAEncryptor) GenerateKeyPair() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	return privateKey, nil
}

// EncryptKey encrypts a symmetric key using RSA-OAEP
func (r *RSAEncryptor) EncryptKey(key []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	encryptedKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		publicKey,
		key,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key with RSA: %w", err)
	}
	return encryptedKey, nil
}

// DecryptKey decrypts a symmetric key using RSA-OAEP
func (r *RSAEncryptor) DecryptKey(encryptedKey []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	key, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privateKey,
		encryptedKey,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key with RSA: %w", err)
	}
	return key, nil
}

// ExportPublicKey exports public key to PEM format
func (r *RSAEncryptor) ExportPublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return pubKeyPEM, nil
}

// ExportPrivateKey exports private key to PEM format
func (r *RSAEncryptor) ExportPrivateKey(privateKey *rsa.PrivateKey) []byte {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return privKeyPEM
}

// ImportPublicKey imports a public key from PEM format
func (r *RSAEncryptor) ImportPublicKey(pubKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPub, nil
}

// ImportPrivateKey imports a private key from PEM format
func (r *RSAEncryptor) ImportPrivateKey(privKeyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}
