package tests

import (
	"bytes"
	"testing"

	"secure-file-encryption/internal/crypto"
)

// AES Tests
func TestAESEncryptor_GenerateKey(t *testing.T) {
	encryptor := crypto.NewAESEncryptor()

	key, err := encryptor.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	key2, err := encryptor.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate second key: %v", err)
	}

	if bytes.Equal(key, key2) {
		t.Error("Generated keys should be unique")
	}
}

func TestAESEncryptor_EncryptDecrypt(t *testing.T) {
	encryptor := crypto.NewAESEncryptor()
	plaintext := []byte("This is a secret message for testing AES encryption!")

	key, err := encryptor.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	ciphertext, nonce, err := encryptor.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	if len(nonce) != 12 {
		t.Errorf("Expected nonce length 12, got %d", len(nonce))
	}

	decrypted, err := encryptor.Decrypt(ciphertext, key, nonce)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s",
			string(plaintext), string(decrypted))
	}
}

func TestAESEncryptor_EncryptWithWrongKeyLength(t *testing.T) {
	encryptor := crypto.NewAESEncryptor()
	plaintext := []byte("Test data")

	wrongKey := []byte("short")
	_, _, err := encryptor.Encrypt(plaintext, wrongKey)
	if err == nil {
		t.Error("Expected error with wrong key length, got nil")
	}
}

func TestAESEncryptor_DecryptWithWrongKey(t *testing.T) {
	encryptor := crypto.NewAESEncryptor()
	plaintext := []byte("Secret message")

	key, _ := encryptor.GenerateKey()
	ciphertext, nonce, err := encryptor.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	wrongKey, _ := encryptor.GenerateKey()
	_, err = encryptor.Decrypt(ciphertext, wrongKey, nonce)
	if err == nil {
		t.Error("Expected error when decrypting with wrong key")
	}
}

func TestAESEncryptor_DecryptWithTamperedData(t *testing.T) {
	encryptor := crypto.NewAESEncryptor()
	plaintext := []byte("Important data")

	key, _ := encryptor.GenerateKey()
	ciphertext, nonce, _ := encryptor.Encrypt(plaintext, key)

	if len(ciphertext) > 0 {
		ciphertext[0] ^= 0xFF
	}

	_, err := encryptor.Decrypt(ciphertext, key, nonce)
	if err == nil {
		t.Error("Expected error when decrypting tampered data")
	}
}

func TestAESEncryptor_EmptyPlaintext(t *testing.T) {
	encryptor := crypto.NewAESEncryptor()
	plaintext := []byte("")

	key, _ := encryptor.GenerateKey()
	ciphertext, nonce, err := encryptor.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt empty data: %v", err)
	}

	decrypted, err := encryptor.Decrypt(ciphertext, key, nonce)
	if err != nil {
		t.Fatalf("Failed to decrypt empty data: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("Decrypted empty data doesn't match")
	}
}

// RSA Tests
func TestRSAEncryptor_GenerateKeyPair(t *testing.T) {
	encryptor := crypto.NewRSAEncryptor()

	privateKey, err := encryptor.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if privateKey.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit key, got %d bits", privateKey.N.BitLen())
	}

	if privateKey.PublicKey.N == nil {
		t.Error("Public key not properly set")
	}
}

func TestRSAEncryptor_EncryptDecryptKey(t *testing.T) {
	encryptor := crypto.NewRSAEncryptor()
	symmetricKey := []byte("This is a 32-byte AES-256 key!!")

	privateKey, err := encryptor.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	encryptedKey, err := encryptor.EncryptKey(symmetricKey, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to encrypt key: %v", err)
	}

	if bytes.Equal(encryptedKey, symmetricKey) {
		t.Error("Encrypted key should differ from original")
	}

	decryptedKey, err := encryptor.DecryptKey(encryptedKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to decrypt key: %v", err)
	}

	if !bytes.Equal(decryptedKey, symmetricKey) {
		t.Error("Decrypted key doesn't match original")
	}
}

func TestRSAEncryptor_DecryptWithWrongKey(t *testing.T) {
	encryptor := crypto.NewRSAEncryptor()
	symmetricKey := []byte("32-byte key for testing purposes")

	privateKey1, _ := encryptor.GenerateKeyPair()
	privateKey2, _ := encryptor.GenerateKeyPair()

	encryptedKey, _ := encryptor.EncryptKey(symmetricKey, &privateKey1.PublicKey)

	_, err := encryptor.DecryptKey(encryptedKey, privateKey2)
	if err == nil {
		t.Error("Expected error when decrypting with wrong private key")
	}
}

func TestRSAEncryptor_ExportImportKeys(t *testing.T) {
	encryptor := crypto.NewRSAEncryptor()

	privateKey, _ := encryptor.GenerateKeyPair()

	privPEM := encryptor.ExportPrivateKey(privateKey)
	pubPEM, err := encryptor.ExportPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	importedPriv, err := encryptor.ImportPrivateKey(privPEM)
	if err != nil {
		t.Fatalf("Failed to import private key: %v", err)
	}

	importedPub, err := encryptor.ImportPublicKey(pubPEM)
	if err != nil {
		t.Fatalf("Failed to import public key: %v", err)
	}

	testData := []byte("Test encryption with imported keys")
	encrypted, _ := encryptor.EncryptKey(testData, importedPub)
	decrypted, err := encryptor.DecryptKey(encrypted, importedPriv)
	if err != nil {
		t.Fatalf("Failed to use imported keys: %v", err)
	}

	if !bytes.Equal(decrypted, testData) {
		t.Error("Imported keys don't work correctly")
	}
}

// Hash Tests
func TestHasher_Hash(t *testing.T) {
	hasher := crypto.NewHasher()
	data := []byte("Test data for hashing")

	hash := hasher.Hash(data)

	if len(hash) != 32 {
		t.Errorf("Expected hash length 32, got %d", len(hash))
	}

	hash2 := hasher.Hash(data)
	if !bytes.Equal(hash, hash2) {
		t.Error("Same data should produce same hash")
	}

	differentData := []byte("Different test data")
	hash3 := hasher.Hash(differentData)
	if bytes.Equal(hash, hash3) {
		t.Error("Different data should produce different hash")
	}
}

func TestHasher_VerifyHash(t *testing.T) {
	hasher := crypto.NewHasher()
	data := []byte("Data to hash and verify")

	hash := hasher.Hash(data)

	err := hasher.VerifyHash(data, hash)
	if err != nil {
		t.Errorf("Hash verification failed: %v", err)
	}

	wrongHash := make([]byte, 32)
	err = hasher.VerifyHash(data, wrongHash)
	if err == nil {
		t.Error("Expected error when verifying wrong hash")
	}

	modifiedData := []byte("Modified data to hash and verify")
	err = hasher.VerifyHash(modifiedData, hash)
	if err == nil {
		t.Error("Expected error when data is modified")
	}
}

func TestHasher_HashFile(t *testing.T) {
	hasher := crypto.NewHasher()
	fileData := []byte("File content for testing")

	hash, err := hasher.HashFile(fileData)
	if err != nil {
		t.Fatalf("HashFile failed: %v", err)
	}

	if len(hash) != 32 {
		t.Errorf("Expected hash length 32, got %d", len(hash))
	}

	_, err = hasher.HashFile([]byte(""))
	if err == nil {
		t.Error("Expected error when hashing empty file")
	}
}

// Digital Signature Tests
func TestSigner_GenerateSigningKey(t *testing.T) {
	signer := crypto.NewSigner()

	privateKey, err := signer.GenerateSigningKey()
	if err != nil {
		t.Fatalf("Failed to generate signing key: %v", err)
	}

	if privateKey.PublicKey.X == nil || privateKey.PublicKey.Y == nil {
		t.Error("Public key not properly set")
	}
}

func TestSigner_SignVerify(t *testing.T) {
	signer := crypto.NewSigner()
	data := []byte("Important document to sign")

	privateKey, _ := signer.GenerateSigningKey()

	signature, err := signer.Sign(data, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	if len(signature) != 64 {
		t.Errorf("Expected signature length 64, got %d", len(signature))
	}

	err = signer.Verify(data, signature, &privateKey.PublicKey)
	if err != nil {
		t.Errorf("Signature verification failed: %v", err)
	}
}

func TestSigner_VerifyWithWrongData(t *testing.T) {
	signer := crypto.NewSigner()
	data := []byte("Original data")
	modifiedData := []byte("Modified data")

	privateKey, _ := signer.GenerateSigningKey()
	signature, _ := signer.Sign(data, privateKey)

	err := signer.Verify(modifiedData, signature, &privateKey.PublicKey)
	if err == nil {
		t.Error("Expected verification to fail with modified data")
	}
}

func TestSigner_VerifyWithWrongKey(t *testing.T) {
	signer := crypto.NewSigner()
	data := []byte("Data to sign")

	privateKey1, _ := signer.GenerateSigningKey()
	privateKey2, _ := signer.GenerateSigningKey()

	signature, _ := signer.Sign(data, privateKey1)

	err := signer.Verify(data, signature, &privateKey2.PublicKey)
	if err == nil {
		t.Error("Expected verification to fail with wrong public key")
	}
}

func TestSigner_VerifyWithTamperedSignature(t *testing.T) {
	signer := crypto.NewSigner()
	data := []byte("Data to sign")

	privateKey, _ := signer.GenerateSigningKey()
	signature, _ := signer.Sign(data, privateKey)

	if len(signature) > 0 {
		signature[0] ^= 0xFF
	}

	err := signer.Verify(data, signature, &privateKey.PublicKey)
	if err == nil {
		t.Error("Expected verification to fail with tampered signature")
	}
}

// KDF Tests
func TestKDF_DeriveKey(t *testing.T) {
	kdf := crypto.NewKDF()
	password := "TestPassword123!"

	key, salt, err := kdf.DeriveKey(password, nil, 100000, 32)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	if len(salt) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(salt))
	}

	key2, _, err := kdf.DeriveKey(password, salt, 100000, 32)
	if err != nil {
		t.Fatalf("Failed to derive key again: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Error("Same password and salt should produce same key")
	}
}

func TestKDF_DifferentPasswords(t *testing.T) {
	kdf := crypto.NewKDF()
	password1 := "Password1"
	password2 := "Password2"

	salt, _ := kdf.GenerateSalt()

	key1, _, _ := kdf.DeriveKey(password1, salt, 100000, 32)
	key2, _, _ := kdf.DeriveKey(password2, salt, 100000, 32)

	if bytes.Equal(key1, key2) {
		t.Error("Different passwords should produce different keys")
	}
}

func TestKDF_DifferentSalts(t *testing.T) {
	kdf := crypto.NewKDF()
	password := "TestPassword"

	key1, salt1, _ := kdf.DeriveKey(password, nil, 100000, 32)
	key2, salt2, _ := kdf.DeriveKey(password, nil, 100000, 32)

	if bytes.Equal(salt1, salt2) {
		t.Error("Generated salts should be different")
	}

	if bytes.Equal(key1, key2) {
		t.Error("Same password with different salts should produce different keys")
	}
}

func TestKDF_InvalidIterations(t *testing.T) {
	kdf := crypto.NewKDF()
	password := "TestPassword"

	_, _, err := kdf.DeriveKey(password, nil, 100, 32)
	if err == nil {
		t.Error("Expected error with too few iterations")
	}
}

func TestKDF_InvalidKeyLength(t *testing.T) {
	kdf := crypto.NewKDF()
	password := "TestPassword"

	_, _, err := kdf.DeriveKey(password, nil, 100000, 8)
	if err == nil {
		t.Error("Expected error with too short key length")
	}
}

func TestKDF_GenerateSalt(t *testing.T) {
	kdf := crypto.NewKDF()

	salt1, err := kdf.GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	if len(salt1) != 32 {
		t.Errorf("Expected salt length 32, got %d", len(salt1))
	}

	salt2, _ := kdf.GenerateSalt()
	if bytes.Equal(salt1, salt2) {
		t.Error("Generated salts should be unique")
	}
}

// Benchmark Tests
func BenchmarkAES_Encrypt(b *testing.B) {
	encryptor := crypto.NewAESEncryptor()
	data := make([]byte, 1024) // 1KB
	key, _ := encryptor.GenerateKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptor.Encrypt(data, key)
	}
}

func BenchmarkAES_Decrypt(b *testing.B) {
	encryptor := crypto.NewAESEncryptor()
	data := make([]byte, 1024)
	key, _ := encryptor.GenerateKey()
	ciphertext, nonce, _ := encryptor.Encrypt(data, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptor.Decrypt(ciphertext, key, nonce)
	}
}

func BenchmarkRSA_Encrypt(b *testing.B) {
	encryptor := crypto.NewRSAEncryptor()
	data := make([]byte, 32)
	privateKey, _ := encryptor.GenerateKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptor.EncryptKey(data, &privateKey.PublicKey)
	}
}

func BenchmarkECDSA_Sign(b *testing.B) {
	signer := crypto.NewSigner()
	data := make([]byte, 1024)
	privateKey, _ := signer.GenerateSigningKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signer.Sign(data, privateKey)
	}
}

func BenchmarkSHA256_Hash(b *testing.B) {
	hasher := crypto.NewHasher()
	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Hash(data)
	}
}

func BenchmarkPBKDF2_DeriveKey(b *testing.B) {
	kdf := crypto.NewKDF()
	password := "TestPassword123!"
	salt, _ := kdf.GenerateSalt()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kdf.DeriveKey(password, salt, 100000, 32)
	}
}
