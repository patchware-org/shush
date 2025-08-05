package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/patchware-org/shush/internal/config"
)

const (
	PrivateKeyFile = "private_key.pem"
	PublicKeyFile  = "public_key.pem"
)

// KeyPair represents a public/private key pair
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// GenerateKeyPair generates a new Ed25519 key pair for E2E encryption
func GenerateKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// SaveKeyPair atomically saves the key pair to the config directory
func SaveKeyPair(keyPair *KeyPair) error {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Use temp names first
	tempPrivate := filepath.Join(configDir, ".tmp_"+PrivateKeyFile)
	tempPublic := filepath.Join(configDir, ".tmp_"+PublicKeyFile)
	finalPrivate := filepath.Join(configDir, PrivateKeyFile)
	finalPublic := filepath.Join(configDir, PublicKeyFile)

	// Save to temp files
	if err := savePrivateKey(keyPair.PrivateKey, tempPrivate); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	if err := savePublicKey(keyPair.PublicKey, tempPublic); err != nil {
		os.Remove(tempPrivate) // cleanup
		return fmt.Errorf("failed to save public key: %w", err)
	}

	// Atomic renames
	if err := os.Rename(tempPrivate, finalPrivate); err != nil {
		os.Remove(tempPrivate)
		os.Remove(tempPublic)
		return fmt.Errorf("failed to finalize private key: %w", err)
	}

	if err := os.Rename(tempPublic, finalPublic); err != nil {
		os.Remove(finalPrivate) // rollback
		os.Remove(tempPublic)
		return fmt.Errorf("failed to finalize public key: %w", err)
	}

	return nil
}

// LoadKeyPair loads the key pair from the config directory
func LoadKeyPair() (*KeyPair, error) {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return nil, err
	}

	privateKeyPath := filepath.Join(configDir, PrivateKeyFile)
	publicKeyPath := filepath.Join(configDir, PublicKeyFile)

	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	publicKey, err := loadPublicKey(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}

	// Validate that the keys are a matching pair
	derivedPublic := privateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPublic, publicKey) {
		return nil, fmt.Errorf("public key doesn't match private key")
	}

	return &KeyPair{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

// KeyPairExists checks if both key files exist
func KeyPairExists() bool {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return false
	}

	privateKeyPath := filepath.Join(configDir, PrivateKeyFile)
	publicKeyPath := filepath.Join(configDir, PublicKeyFile)

	if _, err := os.Stat(privateKeyPath); err != nil {
		return false
	}
	if _, err := os.Stat(publicKeyPath); err != nil {
		return false
	}
	return true
}

// RemoveKeyPair atomically deletes both key files
func RemoveKeyPair() error {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return err
	}

	privateKeyPath := filepath.Join(configDir, PrivateKeyFile)
	publicKeyPath := filepath.Join(configDir, PublicKeyFile)

	// Remove both files, collect errors
	err1 := os.Remove(privateKeyPath)
	err2 := os.Remove(publicKeyPath)

	// Only report errors that aren't "file not found"
	if err1 != nil && !os.IsNotExist(err1) {
		return fmt.Errorf("failed to remove private key: %w", err1)
	}
	if err2 != nil && !os.IsNotExist(err2) {
		return fmt.Errorf("failed to remove public key: %w", err2)
	}

	return nil
}

// GetPublicKeyBytes returns the public key as bytes for sharing/uploading
func (kp *KeyPair) GetPublicKeyBytes() []byte {
	return []byte(kp.PublicKey)
}

// savePrivateKey saves the private key in PEM format
func savePrivateKey(privateKey ed25519.PrivateKey, path string) error {
	// Convert Ed25519 private key to PKCS#8 format
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	privKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %w", err)
	}
	defer file.Close()

	// Set restrictive permissions on the private key file
	if err := file.Chmod(0600); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("failed to set private key file permissions: %w", err)
	}

	if err := pem.Encode(file, privKeyPEM); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Sync to ensure data is written to disk
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync private key file: %w", err)
	}

	return nil
}

// savePublicKey saves the public key in PEM format
func savePublicKey(publicKey ed25519.PublicKey, path string) error {
	// Convert Ed25519 public key to PKIX format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pubKeyPEM); err != nil {
		return fmt.Errorf("failed to encode public key: %w", err)
	}

	// Sync to ensure data is written to disk
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync public key file: %w", err)
	}

	return nil
}

// loadPrivateKey loads the private key from PEM format
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open private key file: %w", err)
	}
	defer file.Close()

	pemData, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}

	return ed25519PrivateKey, nil
}

// loadPublicKey loads the public key from PEM format
func loadPublicKey(path string) (ed25519.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open public key file: %w", err)
	}
	defer file.Close()

	pemData, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ed25519PublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}

	return ed25519PublicKey, nil
}
