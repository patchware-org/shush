package auth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/patchware-org/shush/internal/models"
	"github.com/patchware-org/shush/utils/config"
)

// LoadBackendToken loads the backend token from backend_token.json
func LoadBackendToken() (*models.BackendAuth, error) {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get config directory: %w", err)
	}

	tokenFile := filepath.Join(configDir, config.BackendTokenFile)
	tokenData, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read backend token file: %w", err)
	}

	var backendToken models.BackendAuth
	if err := json.Unmarshal(tokenData, &backendToken); err != nil {
		return nil, fmt.Errorf("failed to parse backend token: %w", err)
	}

	if backendToken.AccessToken == "" {
		return nil, fmt.Errorf("invalid backend token: missing access token")
	}

	return &backendToken, nil
}

// RemoveBackendToken removes the backend token file
func RemoveBackendToken() error {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	tokenFile := filepath.Join(configDir, config.BackendTokenFile)
	if err := os.Remove(tokenFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove backend token file: %w", err)
	}

	return nil
}

// SecureBackendTokenWipe attempts to securely overwrite backend token data before deletion
func SecureBackendTokenWipe() error {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	tokenFile := filepath.Join(configDir, config.BackendTokenFile)

	// Get file info to determine size
	info, err := os.Stat(tokenFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, nothing to wipe
		}
		return fmt.Errorf("failed to stat backend token file: %w", err)
	}

	// Open file for writing
	file, err := os.OpenFile(tokenFile, os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open backend token file for wiping: %w", err)
	}
	defer file.Close()

	// Overwrite with random data multiple times
	size := info.Size()
	for i := 0; i < 3; i++ {
		randomData := make([]byte, size)
		if _, err := rand.Read(randomData); err != nil {
			return fmt.Errorf("failed to generate random data: %w", err)
		}

		if _, err := file.WriteAt(randomData, 0); err != nil {
			return fmt.Errorf("failed to overwrite backend token file: %w", err)
		}

		if err := file.Sync(); err != nil {
			return fmt.Errorf("failed to sync backend token file: %w", err)
		}
	}

	file.Close()

	// Finally remove the file
	return os.Remove(tokenFile)
}

// SaveBackendToken saves a backend token atomically with proper file permissions
func SaveBackendToken(accessToken string, deviceID int64) error {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	backendToken := models.BackendAuth{
		AccessToken: accessToken,
		DeviceID:    deviceID,
	}

	tokenFile := filepath.Join(configDir, config.BackendTokenFile)
	tempFile := tokenFile + ".tmp"

	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create temp backend token file: %w", err)
	}
	defer func() {
		file.Close()
		os.Remove(tempFile) // Clean up on error
	}()

	if err := file.Chmod(0600); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(backendToken); err != nil {
		return fmt.Errorf("failed to encode backend token: %w", err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync backend token file: %w", err)
	}

	file.Close()

	// Atomic rename
	if err := os.Rename(tempFile, tokenFile); err != nil {
		return fmt.Errorf("failed to save backend token file: %w", err)
	}

	return nil
}

// BackendTokenExists checks if a backend token file exists
func BackendTokenExists() bool {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return false
	}

	tokenFile := filepath.Join(configDir, config.BackendTokenFile)
	_, err = os.Stat(tokenFile)
	return err == nil
}
