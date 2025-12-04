# System Architecture

## Overview

The Secure File Encryption System is designed with a layered architecture that separates concerns and promotes modularity, testability, and maintainability.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interface Layer                     │
│                        (CLI Commands)                         │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   Application Layer                          │
│              (File Encryption/Decryption Logic)              │
│                                                              │
│  ┌──────────────┐              ┌──────────────┐            │
│  │ FileEncryptor│              │ FileDecryptor│            │
│  └──────┬───────┘              └──────┬───────┘            │
│         │                              │                     │
└─────────┼──────────────────────────────┼─────────────────────┘
          │                              │
┌─────────▼──────────────────────────────▼─────────────────────┐
│                    Cryptography Layer                         │
│                                                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │    AES     │  │    RSA     │  │   ECDSA    │            │
│  │  Encryptor │  │  Encryptor │  │   Signer   │            │
│  └────────────┘  └────────────┘  └────────────┘            │
│                                                               │
│  ┌────────────┐  ┌────────────┐                             │
│  │   SHA-256  │  │   PBKDF2   │                             │
│  │   Hasher   │  │     KDF    │                             │
│  └────────────┘  └────────────┘                             │
└────────────────────────────┬──────────────────────────────────┘
                             │
┌────────────────────────────▼──────────────────────────────────┐
│                    Key Management Layer                        │
│                                                                │
│  ┌──────────────────────────────────────────────┐            │
│  │            KeyManager                         │            │
│  │  - RSA Key Pair Generation                   │            │
│  │  - ECDSA Key Pair Generation                 │            │
│  │  - Secure Key Storage (PEM format)           │            │
│  │  - Key Loading and Validation                │            │
│  └──────────────────────────────────────────────┘            │
└───────────────────────────────────────────────────────────────┘
```

## Layer Descriptions

### 1. User Interface Layer (CLI)

**Location**: `pkg/cli/commands.go`

**Responsibilities**:
- Parse command-line arguments
- Interact with user (password input, confirmations)
- Display progress and results
- Handle user errors gracefully

**Commands**:
- `generate-keys`: Generate cryptographic keys
- `encrypt [file]`: Encrypt a file
- `decrypt [file]`: Decrypt a file
- `info`: Display system information

**Key Features**:
- Secure password input (hidden echo)
- File path validation
- User-friendly error messages
- Progress indicators

### 2. Application Layer (File Operations)

**Location**: `internal/fileenc/`

**Components**:

#### FileEncryptor
**Responsibilities**:
- Read plaintext files
- Orchestrate encryption process
- Generate file metadata
- Save encrypted files

**Process**:
```
1. Read file → 2. Derive password key → 3. Generate file key
     ↓                                            ↓
4. Encrypt file data ← 5. Encrypt file key ← 6. Sign file
     ↓
7. Compute hash → 8. Package metadata → 9. Save to disk
```

#### FileDecryptor
**Responsibilities**:
- Read encrypted files
- Orchestrate decryption process
- Verify integrity and authenticity
- Save decrypted files

**Process**:
```
1. Read encrypted file → 2. Parse metadata → 3. Decrypt file key
                              ↓                      ↓
                   4. Decrypt file data ← 5. Verify hash & signature
                              ↓
                   6. Save decrypted file
```

### 3. Cryptography Layer

**Location**: `internal/crypto/`

#### AES Encryptor (`aes.go`)
**Algorithm**: AES-256-GCM

**Operations**:
- `Encrypt(plaintext, key)`: Encrypt data with authenticated encryption
- `Decrypt(ciphertext, key, nonce)`: Decrypt and verify authenticity
- `GenerateKey()`: Generate random 256-bit key

**Security Features**:
- Galois/Counter Mode (GCM) for authenticated encryption
- Random nonce generation per encryption
- Automatic authentication tag verification

#### RSA Encryptor (`rsa.go`)
**Algorithm**: RSA-2048 with OAEP padding

**Operations**:
- `GenerateKeyPair()`: Generate 2048-bit RSA key pair
- `EncryptKey(key, publicKey)`: Encrypt symmetric key
- `DecryptKey(encryptedKey, privateKey)`: Decrypt symmetric key
- Export/Import keys in PEM format

**Security Features**:
- OAEP padding with SHA-256
- 2048-bit key size (recommended by NIST)
- Secure key serialization

#### Digital Signer (`signature.go`)
**Algorithm**: ECDSA with P-256 curve

**Operations**:
- `GenerateSigningKey()`: Generate ECDSA key pair
- `Sign(data, privateKey)`: Create digital signature
- `Verify(data, signature, publicKey)`: Verify signature
- Export/Import keys in PEM format

**Security Features**:
- P-256 (secp256r1) elliptic curve
- SHA-256 for message hashing
- ASN.1 signature encoding

#### Hasher (`hash.go`)
**Algorithm**: SHA-256

**Operations**:
- `Hash(data)`: Compute SHA-256 hash
- `VerifyHash(data, expectedHash)`: Verify integrity
- `HashFile(fileData)`: Hash file contents

**Security Features**:
- Constant-time comparison (prevents timing attacks)
- 256-bit hash output

#### Key Derivation Function (`kdf.go`)
**Algorithm**: PBKDF2 with SHA-256

**Operations**:
- `DeriveKey(password, salt, iterations, keyLen)`: Derive key from password
- `GenerateSalt()`: Generate random salt

**Parameters**:
- 100,000 iterations (OWASP recommendation)
- 256-bit salt
- SHA-256 as PRF

### 4. Key Management Layer

**Location**: `internal/keymanager/manager.go`

**Responsibilities**:
- Generate RSA and ECDSA key pairs
- Store keys securely on disk
- Load keys when needed
- Validate key existence

**File Structure**:
```
~/.secure-file-encryption/keys/
├── rsa_private.pem      (0600 permissions)
├── rsa_public.pem       (0644 permissions)
├── ecdsa_private.pem    (0600 permissions)
└── ecdsa_public.pem     (0644 permissions)
```

**Security Measures**:
- Private keys: 0600 permissions (owner read/write only)
- Public keys: 0644 permissions (world-readable)
- PEM format for interoperability
- Directory: 0700 permissions

### 5. Data Models Layer

**Location**: `internal/models/types.go`

**EncryptedFile Structure**:
```go
type EncryptedFile struct {
    Version          string    // Format version
    EncryptedData    []byte    // AES-encrypted file content
    EncryptedKey     []byte    // RSA-encrypted AES key
    Nonce            []byte    // AES-GCM nonce
    Salt             []byte    // PBKDF2 salt
    Hash             []byte    // SHA-256 hash
    Signature        []byte    // ECDSA signature
    OriginalName     string    // Original filename
    OriginalSize     int64     // Original file size
    Timestamp        time.Time // Encryption timestamp
    KDFIterations    int       // PBKDF2 iterations
    EncryptionMethod string    // Algorithm identifier
}
```

## Data Flow

### Encryption Flow

```
┌──────────────┐
│ Plaintext    │
│ File         │
└──────┬───────┘
       │
       ├─────────────────────────────────────────┐
       │                                         │
       ▼                                         ▼
┌──────────────┐                        ┌──────────────┐
│ Password     │                        │ File Data    │
└──────┬───────┘                        └──────┬───────┘
       │                                       │
       ▼                                       ▼
┌──────────────┐                        ┌──────────────┐
│ PBKDF2       │                        │ SHA-256      │
│ (100k iter)  │                        │ Hash         │
└──────┬───────┘                        └──────┬───────┘
       │                                       │
       ▼                                       │
┌──────────────┐                              │
│ Password     │                              │
│ Key (256bit) │                              │
└──────────────┘                              │
                                               │
┌──────────────┐                              │
│ Random AES   │                              │
│ Key (256bit) │                              │
└──────┬───────┘                              │
       │                                       │
       ├───────────────────┐                  │
       │                   │                  │
       ▼                   ▼                  ▼
┌──────────────┐    ┌──────────────┐   ┌──────────────┐
│ AES-256-GCM  │    │ RSA-OAEP     │   │ ECDSA P-256  │
│ Encrypt      │    │ Encrypt Key  │   │ Sign         │
└──────┬───────┘    └──────┬───────┘   └──────┬───────┘
       │                   │                  │
       └───────────────────┴──────────────────┘
                           │
                           ▼
                   ┌──────────────┐
                   │ Encrypted    │
                   │ File Package │
                   └──────────────┘
```

### Decryption Flow

```
┌──────────────┐
│ Encrypted    │
│ File Package │
└──────┬───────┘
       │
       ├─────────────┬─────────────┬─────────────┐
       │             │             │             │
       ▼             ▼             ▼             ▼
┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
│Encrypted │  │Encrypted │  │ Hash     │  │Signature │
│  Data    │  │   Key    │  │          │  │          │
└────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │             │
     │             ▼             │             │
     │      ┌──────────┐         │             │
     │      │ RSA-OAEP │         │             │
     │      │ Decrypt  │         │             │
     │      └────┬─────┘         │             │
     │           │               │             │
     │           ▼               │             │
     │      ┌──────────┐         │             │
     │      │ AES Key  │         │             │
     │      └────┬─────┘         │             │
     │           │               │             │
     └───────────┤               │             │
                 ▼               │             │
          ┌──────────┐           │             │
          │AES-GCM   │           │             │
          │Decrypt   │           │             │
          └────┬─────┘           │             │
               │                 │             │
               ▼                 ▼             ▼
        ┌──────────┐      ┌──────────┐  ┌──────────┐
        │Plaintext │─────▶│ Verify   │  │ Verify   │
        │   Data   │      │ Hash     │  │Signature │
        └──────────┘      └──────────┘  └──────────┘
```

## Design Patterns

### 1. Layered Architecture
- Clear separation of concerns
- Each layer has specific responsibilities
- Dependencies flow downward

### 2. Dependency Injection
- Components receive dependencies via constructors
- Facilitates testing and modularity

### 3. Factory Pattern
- `New*()` functions create configured instances
- Centralizes initialization logic

### 4. Command Pattern
- CLI commands encapsulate operations
- Easy to add new commands

## Security Architecture

### Defense in Depth

1. **Cryptographic Layer**: Multiple algorithms provide redundancy
2. **Key Protection**: Multiple layers of key encryption
3. **Integrity Verification**: Hash + signature
4. **Secure Storage**: Proper file permissions

### Security Boundaries

```
┌─────────────────────────────────────┐
│         Trusted Zone                │
│  ┌───────────────────────────────┐  │
│  │    Application Memory         │  │
│  │  - Plaintext data             │  │
│  │  - Decrypted keys             │  │
│  │  - Passwords (temporary)      │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│      Encrypted Storage Zone         │
│  ┌───────────────────────────────┐  │
│  │    Encrypted Files            │  │
│  │  - No plaintext data          │  │
│  │  - Keys encrypted             │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│       Key Storage Zone              │
│  ┌───────────────────────────────┐  │
│  │    Key Files (0600)           │  │
│  │  - Private keys protected     │  │
│  │  - Restricted access          │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

## Performance Considerations

### Optimization Strategies

1. **Streaming**: Not implemented yet (future enhancement)
2. **Memory Management**: Load entire files (suitable for moderate sizes)
3. **Key Caching**: Keys loaded once per operation

### Scalability

- **File Size**: Currently loads entire file into memory
- **Recommendation**: Files under 100MB work well
- **Future Enhancement**: Implement chunked encryption for large files

## Error Handling

### Error Propagation

```
CLI Layer
    ↓ (user-friendly messages)
Application Layer
    ↓ (context-rich errors)
Crypto Layer
    ↓ (detailed error information)
```

### Error Categories

1. **User Errors**: Invalid input, missing files
2. **Cryptographic Errors**: Decryption failures, verification failures
3. **System Errors**: File I/O errors, permission errors

## Testing Strategy

### Unit Tests
- Test each cryptographic component independently
- Mock dependencies
- Test edge cases

### Integration Tests
- Test complete encrypt/decrypt cycle
- Verify all components work together
- Test error conditions

### Security Tests
- Verify key strengths
- Test integrity verification
- Validate error handling

## Future Enhancements

1. **Streaming Encryption**: Support large files
2. **Compression**: Compress before encryption
3. **Key Rotation**: Support for key updates
4. **Multiple Recipients**: Encrypt for multiple public keys
5. **File Splitting**: Split large files into chunks
6. **Cloud Integration**: Direct encryption to cloud storage
7. **GUI**: Desktop application interface

## Conclusion

The architecture is designed for:
- **Security**: Multiple cryptographic layers
- **Modularity**: Clear separation of concerns
- **Maintainability**: Clean code structure
- **Extensibility**: Easy to add features
- **Testability**: Components can be tested independently