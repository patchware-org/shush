package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Configuration constants for file system footprint
const (
	DefaultConfigDir = "shush"
	TokenCacheFile   = "token_cache.json"
)

// GetConfigDir returns the shush config directory path
func GetConfigDir() (string, error) {
	confDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(confDir, DefaultConfigDir), nil
}
