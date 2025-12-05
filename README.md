# Secure File Encryption System

A robust file encryption system implementing multiple cryptographic primitives for secure file storage and transmission. Built for MAT364 Cryptography course at SDU.

## 🔐 Features

- **AES-256-GCM Encryption**: Authenticated encryption for file data
- **RSA-2048**: Asymmetric encryption for key protection
- **ECDSA P-256**: Digital signatures for authenticity verification
- **PBKDF2**: Password-based key derivation (100,000 iterations)
- **SHA-256**: Cryptographic hashing for integrity verification
- **Metadata Protection**: Original filename and size encryption
- **Secure Key Management**: Encrypted key storage with proper permissions

## 📋 Requirements

- Go 1.21 or higher
- Linux, macOS, or Windows

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/secure-file-encryption.git
cd secure-file-encryption
```

### 2. Initialize Go module and install dependencies

```bash
go mod download
```

### 3. Build the application

```bash
go build -o secure-file-encryption ./cmd/main.go
```

Or run directly:

```bash
go run ./cmd/main.go
```

## 📖 Usage

### 1. Generate Keys

First, generate the required RSA and ECDSA keys:

```bash
./secure-file-encryption generate-keys
```

Keys will be stored in `~/.secure-file-encryption/keys/` by default.

### 2. Encrypt a File

Encrypt a file with password and RSA protection:

```bash
./secure-file-encryption encrypt myfile.txt
# You'll be prompted for a password
```

Options:
- `-o, --output`: Specify output file (default: input + .encrypted)
- `--rsa=false`: Use password-only encryption (no RSA)
- `--key-dir`: Custom key directory

Example with options:

```bash
./secure-file-encryption encrypt document.pdf -o secure_doc.encrypted --key-dir ./my-keys
```

### 3. Decrypt a File

Decrypt an encrypted file:

```bash
./secure-file-encryption decrypt myfile.txt.encrypted
# Enter the same password used for encryption
```

The system will:
- Decrypt the file
- Verify data integrity (SHA-256 hash)
- Verify digital signature (ECDSA)

### 4. System Information

View cryptographic components and key status:

```bash
./secure-file-encryption info
```

## 🏗️ Architecture

```
┌─────────────────┐
│   CLI Layer     │  (User Interface)
└────────┬────────┘
         │
┌────────▼────────┐
│ File Encryption │  (Business Logic)
│   & Decryption  │
└────────┬────────┘
         │
┌────────▼────────┐
│  Crypto Layer   │  (AES, RSA, ECDSA, PBKDF2, SHA-256)
└────────┬────────┘
         │
┌────────▼────────┐
│  Key Manager    │  (Secure Key Storage)
└─────────────────┘
```

### Encryption Flow

1. **Password Input**: User provides password
2. **Key Derivation**: PBKDF2 derives encryption key from password
3. **Key Generation**: Random AES-256 key generated for file
4. **File Encryption**: File encrypted with AES-256-GCM
5. **Key Protection**: AES key encrypted with RSA public key
6. **Hashing**: SHA-256 hash computed for integrity
7. **Signing**: ECDSA signature created for authenticity
8. **Storage**: Encrypted file saved with all metadata

### Decryption Flow

1. **File Loading**: Read encrypted file and metadata
2. **Key Decryption**: Decrypt AES key using RSA private key
3. **File Decryption**: Decrypt file data with AES key
4. **Hash Verification**: Verify SHA-256 hash matches
5. **Signature Verification**: Verify ECDSA signature
6. **Save**: Write decrypted file to disk

## 🔒 Security Features

### Cryptographic Algorithms

| Component | Algorithm | Key Size | Notes |
|-----------|-----------|----------|-------|
| Symmetric Encryption | AES-256-GCM | 256 bits | Authenticated encryption |
| Asymmetric Encryption | RSA-OAEP | 2048 bits | SHA-256 for OAEP |
| Digital Signatures | ECDSA | P-256 curve | SHA-256 for hashing |
| Key Derivation | PBKDF2 | 256 bits | 100,000 iterations |
| Hashing | SHA-256 | 256 bits | File integrity |

### Security Measures

- ✅ **Authenticated Encryption**: GCM mode provides confidentiality and authenticity
- ✅ **Strong Key Derivation**: 100,000 PBKDF2 iterations resist brute-force attacks
- ✅ **Secure Random Generation**: crypto/rand for all random values
- ✅ **Digital Signatures**: ECDSA signatures prevent tampering
- ✅ **Key Protection**: RSA encryption for symmetric keys
- ✅ **Metadata Protection**: Original filename encrypted
- ✅ **Forward Secrecy**: Each file uses unique random key
- ✅ **Secure Permissions**: Key files stored with 0600 permissions

## 📁 Project Structure

```
secure-file-encryption/
├── cmd/
│   └── main.go                 # Application entry point
├── internal/
│   ├── crypto/
│   │   ├── aes.go             # AES-256-GCM implementation
│   │   ├── rsa.go             # RSA-2048 operations
│   │   ├── signature.go       # ECDSA signatures
│   │   ├── hash.go            # SHA-256 hashing
│   │   └── kdf.go             # PBKDF2 key derivation
│   ├── keymanager/
│   │   └── manager.go         # Key generation and storage
│   ├── fileenc/
│   │   ├── encryptor.go       # File encryption logic
│   │   └── decryptor.go       # File decryption logic
│   └── models/
│       └── types.go           # Data structures
├── pkg/
│   └── cli/
│       └── commands.go        # CLI interface
├── docs/
│   ├── architecture.md        # System design
│   ├── security.md           # Security analysis
│   └── user-guide.md         # Detailed usage guide
├── tests/
│   └── integration_test.go   # Integration tests
├── go.mod                     # Go dependencies
├── go.sum
├── .gitignore
└── README.md
```

## 🧪 Testing

Run tests:

```bash
go test ./...
```

Run integration tests:

```bash
go test -v ./tests/
```

Test encryption/decryption:

```bash
# Create test file
echo "Secret message" > test.txt

# Encrypt
./secure-file-encryption encrypt test.txt

# Decrypt
./secure-file-encryption decrypt test.txt.encrypted

# Verify
diff test.txt test.txt.encrypted.decrypted
```

## 📚 Dependencies

- `github.com/spf13/cobra` - CLI framework
- `golang.org/x/crypto` - PBKDF2 implementation
- `golang.org/x/term` - Password input handling

## 🔧 Configuration

### Custom Key Directory

```bash
./secure-file-encryption --key-dir /path/to/keys generate-keys
```

### Password-Only Encryption

```bash
./secure-file-encryption encrypt file.txt --rsa=false
```

## 🛡️ Threat Model

See [docs/security.md](docs/security.md) for detailed security analysis including:
- Threat actors and attack vectors
- Security assumptions
- Potential vulnerabilities
- Mitigation strategies

## 📝 License

MIT License - see LICENSE file

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## ⚠️ Disclaimer

This is an educational project for MAT364 Cryptography course. While it implements industry-standard algorithms correctly, it should not be used for production systems without additional security review and testing.

## 📧 Contact

For questions or issues, please contact:
- Instructor: adil.akhmetov@sdu.edu.kz
- Author: bakdauletbaktygaliyev@gmail.com

## 🙏 Acknowledgments

- SDU MAT364 Cryptography Course
- Go cryptography libraries
- NIST cryptographic standards

---

**Note**: Always backup your encryption keys and remember your passwords. Lost keys or forgotten passwords cannot be recovered!