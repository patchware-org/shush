package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Configuration constants for file system footprint
const (
	DefaultConfigDir = "shush"
	TokenCacheFile   = "token_cache.json"
	BackendTokenFile = "backend_token.json"
	ConfigFile       = "config.json"
	KeysDir          = "keys"
)

// Config represents the CLI configuration
type Config struct {
	BackendURL      string            `json:"backend_url"`
	DefaultTimeout  int               `json:"default_timeout_seconds"`
	AuthProvider    string            `json:"auth_provider"`
	ZitadelIssuer   string            `json:"zitadel_issuer"`
	AuthServiceURL  string            `json:"auth_service_url"`
	ClientID        string            `json:"client_id"`
	Scope           string            `json:"scope"`
	LogLevel        string            `json:"log_level"`
	CustomEndpoints map[string]string `json:"custom_endpoints,omitempty"`
}

var (
	defaultConfig = Config{
		BackendURL:     "http://localhost:8080",
		DefaultTimeout: 30,
		AuthProvider:   "zitadel",
		LogLevel:       "info",
	}
	configOnce   sync.Once
	globalConfig *Config
)

// GetConfigDir returns the shush config directory path
func GetConfigDir() (string, error) {
	confDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(confDir, DefaultConfigDir), nil
}

// GetKeysDir returns the keys directory path
func GetKeysDir() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, KeysDir), nil
}

// EnsureConfigDir creates the config directory if it doesn't exist
func EnsureConfigDir() error {
	configDir, err := GetConfigDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(configDir, 0700)
}

// EnsureKeysDir creates the keys directory if it doesn't exist
func EnsureKeysDir() error {
	keysDir, err := GetKeysDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(keysDir, 0700)
}

// LoadConfig loads configuration from file or environment
func LoadConfig() (*Config, error) {
	configOnce.Do(func() {
		globalConfig = loadConfigInternal()
	})
	return globalConfig, nil
}

func loadConfigInternal() *Config {
	config := defaultConfig

	// Try to load from config file
	if err := loadConfigFromFile(&config); err != nil {
		// Config file doesn't exist or is invalid, use defaults + env
	}

	// Override with environment variables
	loadConfigFromEnv(&config)

	return &config
}

// loadConfigFromFile loads configuration from the config file
func loadConfigFromFile(config *Config) error {
	configDir, err := GetConfigDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(configDir, ConfigFile)
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(config)
}

// loadConfigFromEnv overrides config with environment variables
func loadConfigFromEnv(config *Config) {
	if url := os.Getenv("SHUSH_BACKEND_URL"); url != "" {
		config.BackendURL = url
	}
	if provider := os.Getenv("AUTH_PROVIDER"); provider != "" {
		config.AuthProvider = provider
	}
	if issuer := os.Getenv("ZITADEL_ISSUER"); issuer != "" {
		config.ZitadelIssuer = issuer
	}
	if serviceURL := os.Getenv("AUTH_SERVICE_URL"); serviceURL != "" {
		config.AuthServiceURL = serviceURL
	}
	if clientID := os.Getenv("CLIENT_ID"); clientID != "" {
		config.ClientID = clientID
	}
	if scope := os.Getenv("SCOPE"); scope != "" {
		config.Scope = scope
	}
	if logLevel := os.Getenv("LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}
}

// SaveConfig saves the current configuration to file
func SaveConfig(config *Config) error {
	if err := EnsureConfigDir(); err != nil {
		return err
	}

	configDir, err := GetConfigDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(configDir, ConfigFile)
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}

// GetBackendURL returns the configured backend URL
func GetBackendURL() string {
	config, _ := LoadConfig()
	return config.BackendURL
}

// GetAuthConfig returns authentication configuration
func GetAuthConfig() (string, string, string, string, error) {
	config, err := LoadConfig()
	if err != nil {
		return "", "", "", "", err
	}

	if config.AuthProvider == "" || config.ZitadelIssuer == "" ||
		config.AuthServiceURL == "" || config.ClientID == "" {
		return "", "", "", "", fmt.Errorf("missing required authentication configuration")
	}

	return config.ZitadelIssuer, config.AuthServiceURL, config.ClientID, config.Scope, nil
}
