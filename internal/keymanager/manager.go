package keymanager

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"

	"secure-file-encryption/internal/crypto"
)

// KeyManager manages cryptographic keys
type KeyManager struct {
	rsaEncryptor *crypto.RSAEncryptor
	signer       *crypto.Signer
	keyDir       string
}

// NewKeyManager creates a new key manager
func NewKeyManager(keyDir string) *KeyManager {
	return &KeyManager{
		rsaEncryptor: crypto.NewRSAEncryptor(),
		signer:       crypto.NewSigner(),
		keyDir:       keyDir,
	}
}

// GenerateKeys generates all necessary keys (RSA and ECDSA)
func (km *KeyManager) GenerateKeys() error {
	if err := os.MkdirAll(km.keyDir, 0700); err != nil {
		return fmt.Errorf("failed to create key directory: %w", err)
	}

	rsaPrivKey, err := km.rsaEncryptor.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate RSA keys: %w", err)
	}

	if err := km.SaveRSAKeys(rsaPrivKey); err != nil {
		return fmt.Errorf("failed to save RSA keys: %w", err)
	}

	ecdsaPrivKey, err := km.signer.GenerateSigningKey()
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA keys: %w", err)
	}

	if err := km.SaveSigningKeys(ecdsaPrivKey); err != nil {
		return fmt.Errorf("failed to save ECDSA keys: %w", err)
	}

	fmt.Println("✓ Keys generated successfully")
	fmt.Printf("✓ Keys saved to: %s\n", km.keyDir)
	return nil
}

// SaveRSAKeys saves RSA key pair to files
func (km *KeyManager) SaveRSAKeys(privateKey *rsa.PrivateKey) error {
	privKeyPEM := km.rsaEncryptor.ExportPrivateKey(privateKey)
	pubKeyPEM, err := km.rsaEncryptor.ExportPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	privKeyPath := filepath.Join(km.keyDir, "rsa_private.pem")
	if err := os.WriteFile(privKeyPath, privKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	pubKeyPath := filepath.Join(km.keyDir, "rsa_public.pem")
	if err := os.WriteFile(pubKeyPath, pubKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// SaveSigningKeys saves ECDSA signing key pair to files
func (km *KeyManager) SaveSigningKeys(privateKey *ecdsa.PrivateKey) error {
	privKeyPEM, err := km.signer.ExportSigningKey(privateKey)
	if err != nil {
		return err
	}

	pubKeyPEM, err := km.signer.ExportVerifyingKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	privKeyPath := filepath.Join(km.keyDir, "ecdsa_private.pem")
	if err := os.WriteFile(privKeyPath, privKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write signing key: %w", err)
	}

	pubKeyPath := filepath.Join(km.keyDir, "ecdsa_public.pem")
	if err := os.WriteFile(pubKeyPath, pubKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write verifying key: %w", err)
	}

	return nil
}

// LoadRSAPrivateKey loads RSA private key from file
func (km *KeyManager) LoadRSAPrivateKey() (*rsa.PrivateKey, error) {
	keyPath := filepath.Join(km.keyDir, "rsa_private.pem")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA private key: %w", err)
	}

	privateKey, err := km.rsaEncryptor.ImportPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return privateKey, nil
}

// LoadRSAPublicKey loads RSA public key from file
func (km *KeyManager) LoadRSAPublicKey() (*rsa.PublicKey, error) {
	keyPath := filepath.Join(km.keyDir, "rsa_public.pem")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read RSA public key: %w", err)
	}

	publicKey, err := km.rsaEncryptor.ImportPublicKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	return publicKey, nil
}

// LoadSigningKey loads ECDSA private key from file
func (km *KeyManager) LoadSigningKey() (*ecdsa.PrivateKey, error) {
	keyPath := filepath.Join(km.keyDir, "ecdsa_private.pem")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ECDSA private key: %w", err)
	}

	privateKey, err := km.signer.ImportSigningKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
	}

	return privateKey, nil
}

// LoadVerifyingKey loads ECDSA public key from file
func (km *KeyManager) LoadVerifyingKey() (*ecdsa.PublicKey, error) {
	keyPath := filepath.Join(km.keyDir, "ecdsa_public.pem")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ECDSA public key: %w", err)
	}

	publicKey, err := km.signer.ImportVerifyingKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
	}

	return publicKey, nil
}

// KeysExist checks if keys already exist
func (km *KeyManager) KeysExist() bool {
	rsaPriv := filepath.Join(km.keyDir, "rsa_private.pem")
	rsaPub := filepath.Join(km.keyDir, "rsa_public.pem")
	ecdsaPriv := filepath.Join(km.keyDir, "ecdsa_private.pem")
	ecdsaPub := filepath.Join(km.keyDir, "ecdsa_public.pem")

	_, err1 := os.Stat(rsaPriv)
	_, err2 := os.Stat(rsaPub)
	_, err3 := os.Stat(ecdsaPriv)
	_, err4 := os.Stat(ecdsaPub)

	return err1 == nil && err2 == nil && err3 == nil && err4 == nil
}
