package fileenc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"secure-file-encryption/internal/crypto"
	"secure-file-encryption/internal/keymanager"
	"secure-file-encryption/internal/models"
)

// FileEncryptor handles file encryption operations
type FileEncryptor struct {
	aesEncryptor *crypto.AESEncryptor
	rsaEncryptor *crypto.RSAEncryptor
	hasher       *crypto.Hasher
	signer       *crypto.Signer
	kdf          *crypto.KDF
	keyManager   *keymanager.KeyManager
}

// NewFileEncryptor creates a new file encryptor
func NewFileEncryptor(keyManager *keymanager.KeyManager) *FileEncryptor {
	return &FileEncryptor{
		aesEncryptor: crypto.NewAESEncryptor(),
		rsaEncryptor: crypto.NewRSAEncryptor(),
		hasher:       crypto.NewHasher(),
		signer:       crypto.NewSigner(),
		kdf:          crypto.NewKDF(),
		keyManager:   keyManager,
	}
}

// EncryptFile encrypts a file with password and RSA
func (fe *FileEncryptor) EncryptFile(inputPath, outputPath, password string, useRSA bool) error {
	fmt.Println("Reading file...")
	fileData, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	if len(fileData) == 0 {
		return fmt.Errorf("cannot encrypt empty file")
	}

	fmt.Printf("File size: %d bytes\n", len(fileData))

	fmt.Println("Deriving encryption key from password...")
	passwordKey, salt, err := fe.kdf.DeriveKey(password, nil, 100000, 32)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	fmt.Println("Generating file encryption key...")
	fileKey, err := fe.aesEncryptor.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate file key: %w", err)
	}

	fmt.Println("Encrypting file data...")
	encryptedData, nonce, err := fe.aesEncryptor.Encrypt(fileData, fileKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}

	var encryptedKey []byte
	if useRSA {
		fmt.Println("Encrypting file key with RSA...")
		rsaPubKey, err := fe.keyManager.LoadRSAPublicKey()
		if err != nil {
			return fmt.Errorf("failed to load RSA key: %w", err)
		}
		encryptedKey, err = fe.rsaEncryptor.EncryptKey(fileKey, rsaPubKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt file key with RSA: %w", err)
		}
	} else {
		fmt.Println("Encrypting file key with password...")
		encryptedKey, _, err = fe.aesEncryptor.Encrypt(fileKey, passwordKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt file key: %w", err)
		}
	}

	fmt.Println("Computing file hash...")
	fileHash, err := fe.hasher.HashFile(fileData)
	if err != nil {
		return fmt.Errorf("failed to hash file: %w", err)
	}

	fmt.Println("Creating digital signature...")
	signingKey, err := fe.keyManager.LoadSigningKey()
	if err != nil {
		return fmt.Errorf("failed to load signing key: %w", err)
	}

	signature, err := fe.signer.Sign(fileData, signingKey)
	if err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}

	encryptedFile := &models.EncryptedFile{
		Version:          "1.0",
		EncryptedData:    encryptedData,
		EncryptedKey:     encryptedKey,
		Nonce:            nonce,
		Salt:             salt,
		Hash:             fileHash,
		Signature:        signature,
		OriginalName:     filepath.Base(inputPath),
		OriginalSize:     int64(len(fileData)),
		Timestamp:        time.Now(),
		KDFIterations:    100000,
		EncryptionMethod: "AES-256-GCM",
	}

	fmt.Println("Saving encrypted file...")
	jsonData, err := json.MarshalIndent(encryptedFile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize encrypted file: %w", err)
	}

	if err := os.WriteFile(outputPath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	fmt.Println("✓ File encrypted successfully!")
	fmt.Printf("✓ Output: %s\n", outputPath)
	fmt.Printf("✓ Original size: %d bytes\n", len(fileData))
	fmt.Printf("✓ Encrypted size: %d bytes\n", len(jsonData))

	return nil
}
