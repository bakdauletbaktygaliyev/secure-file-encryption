package tests

import (
	"os"
	"path/filepath"
	"testing"

	"secure-file-encryption/internal/fileenc"
	"secure-file-encryption/internal/keymanager"
)

func TestEncryptDecryptCycle(t *testing.T) {
	tempDir := t.TempDir()
	keyDir := filepath.Join(tempDir, "keys")
	testFile := filepath.Join(tempDir, "test.txt")
	encryptedFile := filepath.Join(tempDir, "test.txt.encrypted")
	decryptedFile := filepath.Join(tempDir, "test.txt.decrypted")

	testData := []byte("This is a secret message for testing!")
	password := "TestPassword123!"

	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	km := keymanager.NewKeyManager(keyDir)
	if err := km.GenerateKeys(); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	t.Run("Encrypt", func(t *testing.T) {
		encryptor := fileenc.NewFileEncryptor(km)
		err := encryptor.EncryptFile(testFile, encryptedFile, password, true)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
			t.Fatal("Encrypted file was not created")
		}
	})

	t.Run("Decrypt", func(t *testing.T) {
		decryptor := fileenc.NewFileDecryptor(km)
		err := decryptor.DecryptFile(encryptedFile, decryptedFile, password, true)
		if err != nil {
			t.Fatalf("Decryption failed: %v", err)
		}

		if _, err := os.Stat(decryptedFile); os.IsNotExist(err) {
			t.Fatal("Decrypted file was not created")
		}

		decryptedData, err := os.ReadFile(decryptedFile)
		if err != nil {
			t.Fatalf("Failed to read decrypted file: %v", err)
		}

		if string(decryptedData) != string(testData) {
			t.Fatalf("Decrypted data doesn't match original.\nExpected: %s\nGot: %s",
				string(testData), string(decryptedData))
		}
	})

	t.Run("WrongPassword", func(t *testing.T) {
		decryptor := fileenc.NewFileDecryptor(km)
		wrongFile := filepath.Join(tempDir, "test.txt.wrong")
		err := decryptor.DecryptFile(encryptedFile, wrongFile, "WrongPassword", true)
		if err == nil {
			t.Fatal("Decryption should have failed with wrong password")
		}
	})
}

func TestEncryptDecryptWithoutRSA(t *testing.T) {
	tempDir := t.TempDir()
	keyDir := filepath.Join(tempDir, "keys")
	testFile := filepath.Join(tempDir, "test.txt")
	encryptedFile := filepath.Join(tempDir, "test.txt.encrypted")
	decryptedFile := filepath.Join(tempDir, "test.txt.decrypted")

	testData := []byte("Testing password-only encryption!")
	password := "SecurePassword456!"

	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	km := keymanager.NewKeyManager(keyDir)
	if err := km.GenerateKeys(); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	encryptor := fileenc.NewFileEncryptor(km)
	if err := encryptor.EncryptFile(testFile, encryptedFile, password, false); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptor := fileenc.NewFileDecryptor(km)
	if err := decryptor.DecryptFile(encryptedFile, decryptedFile, password, false); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	decryptedData, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if string(decryptedData) != string(testData) {
		t.Fatalf("Decrypted data doesn't match original")
	}
}

func TestLargeFile(t *testing.T) {
	tempDir := t.TempDir()
	keyDir := filepath.Join(tempDir, "keys")
	testFile := filepath.Join(tempDir, "large.txt")
	encryptedFile := filepath.Join(tempDir, "large.txt.encrypted")
	decryptedFile := filepath.Join(tempDir, "large.txt.decrypted")

	testData := make([]byte, 1024*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	password := "LargeFilePassword789!"

	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	km := keymanager.NewKeyManager(keyDir)
	if err := km.GenerateKeys(); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	encryptor := fileenc.NewFileEncryptor(km)
	if err := encryptor.EncryptFile(testFile, encryptedFile, password, true); err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptor := fileenc.NewFileDecryptor(km)
	if err := decryptor.DecryptFile(encryptedFile, decryptedFile, password, true); err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	decryptedData, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if len(decryptedData) != len(testData) {
		t.Fatalf("Size mismatch: expected %d, got %d", len(testData), len(decryptedData))
	}

	for i := 0; i < len(testData); i += 1000 {
		if decryptedData[i] != testData[i] {
			t.Fatalf("Data mismatch at position %d", i)
		}
	}
}

func BenchmarkEncryption(b *testing.B) {
	tempDir := b.TempDir()
	keyDir := filepath.Join(tempDir, "keys")
	testFile := filepath.Join(tempDir, "bench.txt")
	encryptedFile := filepath.Join(tempDir, "bench.txt.encrypted")

	testData := []byte("Benchmark data for performance testing!")
	password := "BenchPassword!"

	os.WriteFile(testFile, testData, 0644)

	km := keymanager.NewKeyManager(keyDir)
	km.GenerateKeys()

	encryptor := fileenc.NewFileEncryptor(km)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptor.EncryptFile(testFile, encryptedFile, password, true)
	}
}

func BenchmarkDecryption(b *testing.B) {
	tempDir := b.TempDir()
	keyDir := filepath.Join(tempDir, "keys")
	testFile := filepath.Join(tempDir, "bench.txt")
	encryptedFile := filepath.Join(tempDir, "bench.txt.encrypted")
	decryptedFile := filepath.Join(tempDir, "bench.txt.decrypted")

	testData := []byte("Benchmark data for performance testing!")
	password := "BenchPassword!"

	os.WriteFile(testFile, testData, 0644)

	km := keymanager.NewKeyManager(keyDir)
	km.GenerateKeys()

	encryptor := fileenc.NewFileEncryptor(km)
	encryptor.EncryptFile(testFile, encryptedFile, password, true)

	decryptor := fileenc.NewFileDecryptor(km)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decryptor.DecryptFile(encryptedFile, decryptedFile, password, true)
	}
}
