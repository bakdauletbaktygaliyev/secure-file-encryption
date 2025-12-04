package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"secure-file-encryption/internal/fileenc"
	"secure-file-encryption/internal/keymanager"
)

var (
	keyDir     string
	useRSA     bool
	outputFile string
)

var rootCmd = &cobra.Command{
	Use:   "secure-file-encryption",
	Short: "Secure File Encryption System",
	Long: `A secure file encryption system implementing AES-256-GCM, RSA, ECDSA signatures,
and PBKDF2 key derivation. Protects file confidentiality, integrity, and authenticity.`,
}

var generateKeysCmd = &cobra.Command{
	Use:   "generate-keys",
	Short: "Generate RSA and ECDSA key pairs",
	Long:  `Generates RSA-2048 key pair for encryption and ECDSA P-256 key pair for digital signatures.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		km := keymanager.NewKeyManager(keyDir)

		if km.KeysExist() {
			fmt.Println("Warning: Keys already exist in", keyDir)
			fmt.Print("Overwrite? (yes/no): ")
			var response string
			fmt.Scanln(&response)
			if response != "yes" {
				fmt.Println("Key generation cancelled.")
				return nil
			}
		}

		return km.GenerateKeys()
	},
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt [input-file]",
	Short: "Encrypt a file",
	Long:  `Encrypts a file using AES-256-GCM with password-based or RSA key encryption.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputFile := args[0]

		if _, err := os.Stat(inputFile); os.IsNotExist(err) {
			return fmt.Errorf("input file does not exist: %s", inputFile)
		}

		if outputFile == "" {
			outputFile = inputFile + ".encrypted"
		}

		km := keymanager.NewKeyManager(keyDir)
		if !km.KeysExist() {
			return fmt.Errorf("keys not found. Please run 'generate-keys' first")
		}

		password, err := getPassword("Enter encryption password: ")
		if err != nil {
			return err
		}

		confirmPassword, err := getPassword("Confirm password: ")
		if err != nil {
			return err
		}

		if password != confirmPassword {
			return fmt.Errorf("passwords do not match")
		}

		encryptor := fileenc.NewFileEncryptor(km)
		return encryptor.EncryptFile(inputFile, outputFile, password, useRSA)
	},
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt [encrypted-file]",
	Short: "Decrypt a file",
	Long:  `Decrypts an encrypted file and verifies its integrity and signature.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputFile := args[0]

		if _, err := os.Stat(inputFile); os.IsNotExist(err) {
			return fmt.Errorf("encrypted file does not exist: %s", inputFile)
		}

		if outputFile == "" {
			base := filepath.Base(inputFile)
			if filepath.Ext(base) == ".encrypted" {
				outputFile = base[:len(base)-len(".encrypted")]
			} else {
				outputFile = inputFile + ".decrypted"
			}
		}

		km := keymanager.NewKeyManager(keyDir)
		if !km.KeysExist() {
			return fmt.Errorf("keys not found. Please run 'generate-keys' first")
		}

		password, err := getPassword("Enter decryption password: ")
		if err != nil {
			return err
		}

		decryptor := fileenc.NewFileDecryptor(km)
		return decryptor.DecryptFile(inputFile, outputFile, password, useRSA)
	},
}

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display system information",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("Secure File Encryption System v1.0")
		fmt.Println("===================================")
		fmt.Println()
		fmt.Println("Cryptographic Components:")
		fmt.Println("  • Symmetric Encryption: AES-256-GCM")
		fmt.Println("  • Asymmetric Encryption: RSA-2048 with OAEP")
		fmt.Println("  • Digital Signatures: ECDSA P-256")
		fmt.Println("  • Hash Function: SHA-256")
		fmt.Println("  • Key Derivation: PBKDF2 (100,000 iterations)")
		fmt.Println()
		fmt.Printf("Key Directory: %s\n", keyDir)

		km := keymanager.NewKeyManager(keyDir)
		if km.KeysExist() {
			fmt.Println("Keys Status: ✓ Keys found")
		} else {
			fmt.Println("Keys Status: ✗ Keys not found (run 'generate-keys')")
		}

		return nil
	},
}

func init() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	defaultKeyDir := filepath.Join(homeDir, ".secure-file-encryption", "keys")

	rootCmd.PersistentFlags().StringVar(&keyDir, "key-dir", defaultKeyDir, "Directory for key storage")

	encryptCmd.Flags().BoolVar(&useRSA, "rsa", true, "Use RSA for key encryption (default: true)")
	encryptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: input + .encrypted)")

	decryptCmd.Flags().BoolVar(&useRSA, "rsa", true, "Use RSA for key decryption (default: true)")
	decryptCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")

	rootCmd.AddCommand(generateKeysCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(infoCmd)
}

// Execute runs the CLI
func Execute() error {
	return rootCmd.Execute()
}

// getPassword prompts for password without echoing
func getPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(passwordBytes), nil
}
