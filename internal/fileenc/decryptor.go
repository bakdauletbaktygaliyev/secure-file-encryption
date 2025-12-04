package fileenc

import (
	"encoding/json"
	"fmt"
	"os"

	"secure-file-encryption/internal/crypto"
	"secure-file-encryption/internal/keymanager"
	"secure-file-encryption/internal/models"
)

// FileDecryptor handles file decryption operations
type FileDecryptor struct {
	aesEncryptor *crypto.AESEncryptor
	rsaEncryptor *crypto.RSAEncryptor
	hasher       *crypto.Hasher
	signer       *crypto.Signer
	kdf          *crypto.KDF
	keyManager   *keymanager.KeyManager
}

// NewFileDecryptor creates a new file decryptor
func NewFileDecryptor(keyManager *keymanager.KeyManager) *FileDecryptor {
	return &FileDecryptor{
		aesEncryptor: crypto.NewAESEncryptor(),
		rsaEncryptor: crypto.NewRSAEncryptor(),
		hasher:       crypto.NewHasher(),
		signer:       crypto.NewSigner(),
		kdf:          crypto.NewKDF(),
		keyManager:   keyManager,
	}
}

// DecryptFile decrypts an encrypted file
func (fd *FileDecryptor) DecryptFile(inputPath, outputPath, password string, useRSA bool) error {
	fmt.Println("Reading encrypted file...")
	jsonData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	var encryptedFile models.EncryptedFile
	if err := json.Unmarshal(jsonData, &encryptedFile); err != nil {
		return fmt.Errorf("failed to parse encrypted file: %w", err)
	}

	fmt.Printf("Encrypted file version: %s\n", encryptedFile.Version)
	fmt.Printf("Original file: %s (%d bytes)\n", encryptedFile.OriginalName, encryptedFile.OriginalSize)

	var fileKey []byte
	if useRSA {
		fmt.Println("Decrypting file key with RSA...")
		rsaPrivKey, err := fd.keyManager.LoadRSAPrivateKey()
		if err != nil {
			return fmt.Errorf("failed to load RSA private key: %w", err)
		}
		fileKey, err = fd.rsaEncryptor.DecryptKey(encryptedFile.EncryptedKey, rsaPrivKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt file key: %w", err)
		}
	} else {
		fmt.Println("Deriving decryption key from password...")
		passwordKey, _, err := fd.kdf.DeriveKey(password, encryptedFile.Salt, encryptedFile.KDFIterations, 32)
		if err != nil {
			return fmt.Errorf("failed to derive key: %w", err)
		}

		fmt.Println("Decrypting file key with password...")
		if len(encryptedFile.EncryptedKey) < 12 {
			return fmt.Errorf("invalid encrypted key format")
		}
		keyNonceSize := 12
		keyData := encryptedFile.EncryptedKey[:len(encryptedFile.EncryptedKey)-keyNonceSize]
		keyNonce := encryptedFile.EncryptedKey[len(encryptedFile.EncryptedKey)-keyNonceSize:]

		fileKey, err = fd.aesEncryptor.Decrypt(keyData, passwordKey, keyNonce)
		if err != nil {
			return fmt.Errorf("failed to decrypt file key (wrong password?): %w", err)
		}
	}

	fmt.Println("Decrypting file data...")
	decryptedData, err := fd.aesEncryptor.Decrypt(encryptedFile.EncryptedData, fileKey, encryptedFile.Nonce)
	if err != nil {
		return fmt.Errorf("failed to decrypt file data: %w", err)
	}

	fmt.Println("Verifying file integrity...")
	if err := fd.hasher.VerifyHash(decryptedData, encryptedFile.Hash); err != nil {
		return fmt.Errorf("integrity check failed: %w", err)
	}

	fmt.Println("Verifying digital signature...")
	verifyingKey, err := fd.keyManager.LoadVerifyingKey()
	if err != nil {
		return fmt.Errorf("failed to load verifying key: %w", err)
	}

	if err := fd.signer.Verify(decryptedData, encryptedFile.Signature, verifyingKey); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	fmt.Println("Saving decrypted file...")
	if err := os.WriteFile(outputPath, decryptedData, 0644); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	fmt.Println("✓ File decrypted successfully!")
	fmt.Printf("✓ Output: %s\n", outputPath)
	fmt.Printf("✓ File integrity: VERIFIED\n")
	fmt.Printf("✓ Digital signature: VERIFIED\n")

	return nil
}
