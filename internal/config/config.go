package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Config represents the main shush configuration
type Config struct {
	Version     string  `json:"version"`
	ProjectName string  `json:"project_name"`
	Scopes      []Scope `json:"scopes"`
}

// Scope represents a secrets scope
type Scope struct {
	Name    string   `json:"name"`
	Remote  string   `json:"remote,omitempty"`
	Secrets []Secret `json:"secrets"`
}

// Secret represents a secret entry
type Secret struct {
	Path   string `json:"path"`
	Format string `json:"format"`
}

// Configuration constants for file system footprint
const (
	GlobalConfigDir = ".shush"
	GlobalConfigFile = "config.json"
	LocalConfigDir  = ".shush"
	LocalConfigFile = "config.json"
	DefaultProjectName = "shush-project"

	TokenCacheFile   = "token_cache.json"
)

// GetConfigDir returns the shush config directory path
func GetConfigDir() (string, error) {
	confDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(confDir, GlobalConfigDir), nil
}
