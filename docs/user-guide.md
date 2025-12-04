# User Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Key Management](#key-management)
3. [Encrypting Files](#encrypting-files)
4. [Decrypting Files](#decrypting-files)
5. [Advanced Usage](#advanced-usage)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)
8. [FAQ](#faq)

## Getting Started

### Installation

1. **Install Go** (version 1.21 or higher)
   ```bash
   # Check Go version
   go version
   ```

2. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/secure-file-encryption.git
   cd secure-file-encryption
   ```

3. **Install dependencies**
   ```bash
   go mod download
   ```

4. **Build the application**
   ```bash
   go build -o secure-file-encryption ./cmd/main.go
   ```

5. **Verify installation**
   ```bash
   ./secure-file-encryption info
   ```

### First-Time Setup

Before encrypting any files, you must generate cryptographic keys:

```bash
./secure-file-encryption generate-keys
```

This creates:
- RSA-2048 key pair for encryption
- ECDSA P-256 key pair for signatures
- Keys stored in `~/.secure-file-encryption/keys/`

**Important**: Back up these keys securely! Lost keys mean lost access to encrypted files.

## Key Management

### Generating Keys

```bash
# Generate keys in default location
./secure-file-encryption generate-keys

# Generate keys in custom location
./secure-file-encryption --key-dir /path/to/keys generate-keys
```

### Key Storage

Keys are stored in PEM format:

```
~/.secure-file-encryption/keys/
├── rsa_private.pem      # RSA private key (0600)
├── rsa_public.pem       # RSA public key (0644)
├── ecdsa_private.pem    # ECDSA private key (0600)
└── ecdsa_public.pem     # ECDSA public key (0644)
```

### Backing Up Keys

**Critical**: Always backup your keys!

```bash
# Create encrypted backup
tar -czf keys-backup.tar.gz ~/.secure-file-encryption/keys/

# Store in multiple secure locations:
# - External encrypted USB drive
# - Secure cloud storage
# - Offline backup
```

### Restoring Keys

```bash
# Extract keys to correct location
tar -xzf keys-backup.tar.gz -C ~/

# Verify permissions
chmod 700 ~/.secure-file-encryption/keys/
chmod 600 ~/.secure-file-encryption/keys/*_private.pem
chmod 644 ~/.secure-file-encryption/keys/*_public.pem
```

### Rotating Keys

For enhanced security, periodically generate new keys:

```bash
# Backup old keys
mv ~/.secure-file-encryption/keys ~/.secure-file-encryption/keys.old

# Generate new keys
./secure-file-encryption generate-keys

# Re-encrypt important files with new keys
```

## Encrypting Files

### Basic Encryption

```bash
# Encrypt a file
./secure-file-encryption encrypt myfile.txt

# You'll be prompted for password:
# Enter encryption password: ********
# Confirm password: ********

# Output: myfile.txt.encrypted
```

### Encryption with Custom Output

```bash
# Specify output file
./secure-file-encryption encrypt document.pdf -o secure_document.enc

# Specify custom key directory
./secure-file-encryption --key-dir /path/to/keys encrypt file.txt
```

### Password-Only Encryption

Skip RSA encryption (faster, but less secure):

```bash
./secure-file-encryption encrypt file.txt --rsa=false
```

### Batch Encryption

Encrypt multiple files:

```bash
#!/bin/bash
for file in *.txt; do
    ./secure-file-encryption encrypt "$file"
done
```

### What Gets Encrypted?

When you encrypt a file, the system:

1. ✅ Encrypts file content with AES-256-GCM
2. ✅ Encrypts original filename
3. ✅ Creates SHA-256 hash for integrity
4. ✅ Creates ECDSA signature for authenticity
5. ✅ Encrypts encryption key with RSA
6. ✅ Stores all metadata in JSON format

**Note**: File size is NOT hidden (visible in encrypted file).

## Decrypting Files

### Basic Decryption

```bash
# Decrypt a file
./secure-file-encryption decrypt myfile.txt.encrypted

# Enter password:
# Enter decryption password: ********

# Output: myfile.txt (or myfile.txt.encrypted.decrypted)
```

### Decryption with Custom Output

```bash
# Specify output file
./secure-file-encryption decrypt secure_doc.enc -o document.pdf

# Use custom key directory
./secure-file-encryption --key-dir /path/to/keys decrypt file.txt.encrypted
```

### Verification Process

During decryption, the system automatically:

1. ✅ Decrypts the encryption key
2. ✅ Decrypts the file content
3. ✅ **Verifies SHA-256 hash** (detects tampering)
4. ✅ **Verifies ECDSA signature** (confirms authenticity)

If verification fails, decryption is aborted.

### Batch Decryption

```bash
#!/bin/bash
for file in *.encrypted; do
    ./secure-file-encryption decrypt "$file"
done
```

## Advanced Usage

### Using Custom Key Directories

Useful for multiple identities or projects:

```bash
# Project-specific keys
./secure-file-encryption --key-dir ./project-keys generate-keys
./secure-file-encryption --key-dir ./project-keys encrypt file.txt

# Personal keys
./secure-file-encryption --key-dir ~/.personal-keys encrypt personal.txt
```

### Encrypting Different File Types

The system works with any file type:

```bash
# Documents
./secure-file-encryption encrypt report.docx
./secure-file-encryption encrypt presentation.pptx

# Images
./secure-file-encryption encrypt photo.jpg
./secure-file-encryption encrypt design.png

# Archives
./secure-file-encryption encrypt backup.tar.gz
./secure-file-encryption encrypt project.zip

# Databases
./secure-file-encryption encrypt database.sqlite
```

### Creating Encrypted Archives

Combine multiple files:

```bash
# Create archive
tar -czf archive.tar.gz file1.txt file2.txt file3.txt

# Encrypt archive
./secure-file-encryption encrypt archive.tar.gz

# Later: decrypt and extract
./secure-file-encryption decrypt archive.tar.gz.encrypted
tar -xzf archive.tar.gz
```

### Shell Scripts

#### Encryption Script

```bash
#!/bin/bash
# encrypt-files.sh

KEY_DIR="$HOME/.secure-file-encryption/keys"
TOOL="./secure-file-encryption"

if [ ! -d "$KEY_DIR" ]; then
    echo "Generating keys..."
    $TOOL generate-keys
fi

for file in "$@"; do
    if [ -f "$file" ]; then
        echo "Encrypting: $file"
        $TOOL encrypt "$file"
        
        if [ $? -eq 0 ]; then
            echo "✓ Encrypted: $file.encrypted"
            # Optional: remove original
            # rm "$file"
        else
            echo "✗ Failed: $file"
        fi
    fi
done
```

Usage:
```bash
chmod +x encrypt-files.sh
./encrypt-files.sh file1.txt file2.pdf file3.docx
```

#### Decryption Script

```bash
#!/bin/bash
# decrypt-files.sh

TOOL="./secure-file-encryption"

for file in "$@"; do
    if [ -f "$file" ]; then
        echo "Decrypting: $file"
        $TOOL decrypt "$file"
        
        if [ $? -eq 0 ]; then
            echo "✓ Decrypted: ${file%.encrypted}"
        else
            echo "✗ Failed: $file"
        fi
    fi
done
```

## Troubleshooting

### Common Issues

#### "Keys not found"

**Problem**: Keys don't exist
**Solution**:
```bash
./secure-file-encryption generate-keys
```

#### "Decryption failed (wrong key or corrupted data)"

**Possible causes**:
1. Wrong password
2. Corrupted file
3. Wrong keys used

**Solutions**:
```bash
# Verify password
# Try with correct keys
./secure-file-encryption --key-dir /correct/path decrypt file.encrypted

# Check file integrity
ls -lh file.encrypted  # Check if file size is reasonable
```

#### "Failed to read encrypted file"

**Problem**: File doesn't exist or no permission
**Solution**:
```bash
# Check file exists
ls -l file.encrypted

# Check permissions
chmod 644 file.encrypted
```

#### "Signature verification failed"

**Problem**: File has been tampered with
**Solution**:
- **DO NOT use this file**
- File integrity compromised
- Restore from backup

#### "Permission denied"

**Problem**: Insufficient file permissions
**Solution**:
```bash
# For input files
chmod 644 input-file

# For key directory
chmod 700 ~/.secure-file-encryption/keys/
chmod 600 ~/.secure-file-encryption/keys/*_private.pem
```

### Performance Issues

#### Slow Encryption

**Cause**: Large files or slow disk
**Solutions**:
- Use SSD for better performance
- Encrypt smaller files
- Use `--rsa=false` for faster encryption (less secure)

#### Out of Memory

**Cause**: File too large
**Current Limitation**: Files loaded entirely into memory
**Solution**: Split large files:

```bash
# Split large file
split -b 50M largefile.dat chunk_

# Encrypt chunks
for chunk in chunk_*; do
    ./secure-file-encryption encrypt "$chunk"
done
```

### Getting Help

1. **Check system info**
   ```bash
   ./secure-file-encryption info
   ```

2. **Verbose mode** (if implemented)
   ```bash
   ./secure-file-encryption encrypt file.txt --verbose
   ```

3. **Contact support**
    - GitHub Issues: [repository URL]
    - Email: [your email]

## Best Practices

### Password Security

✅ **DO**:
- Use long passphrases (12+ characters)
- Use unique passwords per file/category
- Use password manager
- Mix uppercase, lowercase, numbers, symbols
- Use memorable phrases: "MyDog-Ate-7-Cookies-Today!"

❌ **DON'T**:
- Reuse passwords
- Use dictionary words alone
- Use personal information
- Share passwords
- Write passwords in plaintext

### Key Management

✅ **DO**:
- Backup keys regularly
- Store backups in multiple locations
- Use encrypted USB drives for backups
- Protect private keys (never share)
- Rotate keys periodically

❌ **DON'T**:
- Store keys in cloud without encryption
- Email keys
- Share private keys
- Leave keys on shared computers
- Lose keys (unrecoverable!)

### File Handling

✅ **DO**:
- Verify decryption before deleting original
- Keep encrypted files in secure locations
- Use descriptive names: `document_2024.pdf.encrypted`
- Document what was encrypted
- Regular backups

❌ **DON'T**:
- Delete originals immediately after encryption
- Store encrypted files and keys together
- Trust corrupted files
- Ignore verification failures

### System Security

✅ **DO**:
- Use full disk encryption
- Keep system updated
- Use antivirus software
- Lock screen when away
- Use secure boot

❌ **DON'T**:
- Use on compromised systems
- Disable firewall
- Run as administrator unnecessarily
- Download from untrusted sources

## FAQ

### General Questions

**Q: Is this production-ready?**
A: This is an educational project. While it uses industry-standard algorithms correctly, it should undergo security audit before production use.

**Q: Can I recover files if I forget the password?**
A: No. Encryption is designed to be irreversible without the password.

**Q: Can I share encrypted files?**
A: Yes, but recipients need:
- The encrypted file
- Your public keys (for verification)
- The password

**Q: How secure is this?**
A: Uses AES-256, RSA-2048, ECDSA P-256 - all industry-standard algorithms. Security depends on password strength and key protection.

### Technical Questions

**Q: What encryption is used?**
A:
- Symmetric: AES-256-GCM
- Asymmetric: RSA-2048-OAEP
- Signatures: ECDSA P-256
- Hashing: SHA-256
- KDF: PBKDF2 (100,000 iterations)

**Q: Can I use without RSA?**
A: Yes, use `--rsa=false` flag. This uses only password-based encryption (faster but less secure).

**Q: What's the file size limit?**
A: Limited by available memory. Works well for files under 100MB.

**Q: Is the filename encrypted?**
A: Original filename is stored in metadata but the encrypted file keeps original name + .encrypted.

**Q: Are keys quantum-resistant?**
A: No. RSA and ECDSA are vulnerable to quantum computers. AES-256 has reduced security (64-bit) against quantum attacks.

### Usage Questions

**Q: Can I encrypt directories?**
A: Not directly. Create tar archive first:
```bash
tar -czf dir.tar.gz my-directory/
./secure-file-encryption encrypt dir.tar.gz
```

**Q: Can I automate encryption?**
A: Yes, but storing passwords in scripts is risky. Consider environment variables:
```bash
export ENCRYPT_PASSWORD="secret"
echo "$ENCRYPT_PASSWORD" | ./secure-file-encryption encrypt file.txt
```

**Q: Can I use different keys for different files?**
A: Yes, use `--key-dir` flag with different directories.

**Q: How do I share files securely?**
A:
1. Encrypt file
2. Share encrypted file via any method
3. Share password via separate secure channel
4. Share public keys for verification

---

## Quick Reference

### Common Commands

```bash
# Generate keys
./secure-file-encryption generate-keys

# Encrypt
./secure-file-encryption encrypt file.txt

# Decrypt
./secure-file-encryption decrypt file.txt.encrypted

# Info
./secure-file-encryption info

# Custom key directory
./secure-file-encryption --key-dir /path/to/keys [command]

# Password-only mode
./secure-file-encryption encrypt file.txt --rsa=false

# Custom output
./secure-file-encryption encrypt file.txt -o output.enc
```

### Key Shortcuts

```bash
# Backup keys
tar -czf keys-backup.tar.gz ~/.secure-file-encryption/keys/

# Restore keys
tar -xzf keys-backup.tar.gz -C ~/

# Check keys exist
ls -la ~/.secure-file-encryption/keys/
```

---

For more information, see:
- [README.md](../README.md) - Project overview
- [architecture.md](architecture.md) - System design
- [security.md](security.md) - Security analysis