package auth

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/patchware-org/shush/utils/config"
)

// Token represents a standardized token structure
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	IssuedAt     time.Time `json:"issued_at"`
	RefreshAt    time.Time `json:"refresh_at"`
}

var (
	tokenMutex  sync.RWMutex
	cachedToken *Token
	tokenExpiry time.Time
)

// getOAuthTokenCacheFile returns the path to the token cache file
func getOAuthTokenCacheFile() (string, error) {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, config.TokenCacheFile), nil
}

// SaveOAuthToken saves the token to the file system with atomic writes
func SaveOAuthToken(tokenResp *TokenResponse) error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	cacheFile, err := getOAuthTokenCacheFile()
	if err != nil {
		return err
	}

	if err := config.EnsureConfigDir(); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	now := time.Now()
	refreshBuffer := 5 * time.Minute // Refresh 5 minutes before expiry
	expiresAt := now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	token := &Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    expiresAt,
		IssuedAt:     now,
		RefreshAt:    expiresAt.Add(-refreshBuffer),
	}

	// Atomic write using temporary file
	tempFile := cacheFile + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("failed to create temp token cache file: %w", err)
	}
	defer func() {
		file.Close()
		os.Remove(tempFile) // Clean up temp file on error
	}()

	// Set restrictive permissions on the token file
	if err := file.Chmod(0600); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(token); err != nil {
		return fmt.Errorf("failed to encode token: %w", err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync token file: %w", err)
	}

	file.Close()

	// Atomic rename
	if err := os.Rename(tempFile, cacheFile); err != nil {
		return fmt.Errorf("failed to save token file: %w", err)
	}

	// Update cached token
	cachedToken = token
	tokenExpiry = token.ExpiresAt

	return nil
}

// LoadOAuthToken loads the cached token from the file system
func LoadOAuthToken() (*Token, error) {
	tokenMutex.RLock()

	// Return cached token if still valid
	if cachedToken != nil && time.Now().Before(tokenExpiry) {
		defer tokenMutex.RUnlock()
		return cachedToken, nil
	}
	tokenMutex.RUnlock()

	// Need to reload from disk
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	// Double-check after acquiring write lock
	if cachedToken != nil && time.Now().Before(tokenExpiry) {
		return cachedToken, nil
	}

	cacheFile, err := getOAuthTokenCacheFile()
	if err != nil {
		return nil, err
	}

	file, err := os.Open(cacheFile)
	if err != nil {
		cachedToken = nil
		return nil, fmt.Errorf("failed to open token cache file: %w", err)
	}
	defer file.Close()

	var token Token
	if err := json.NewDecoder(file).Decode(&token); err != nil {
		cachedToken = nil
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	// Validate token structure
	if token.AccessToken == "" {
		cachedToken = nil
		return nil, fmt.Errorf("invalid token: missing access token")
	}

	cachedToken = &token
	tokenExpiry = token.ExpiresAt

	return &token, nil
}

// RemoveOAuthToken deletes the cached token file and clears cache
func RemoveOAuthToken() error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	cacheFile, err := getOAuthTokenCacheFile()
	if err != nil {
		return err
	}

	// Clear cached token first
	cachedToken = nil
	tokenExpiry = time.Time{}

	if err := os.Remove(cacheFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove token cache file: %w", err)
	}

	return nil
}

// IsOAuthTokenValid checks if the cached token exists and is not expired
func IsOAuthTokenValid() bool {
	token, err := LoadOAuthToken()
	if err != nil {
		return false
	}

	// Consider token invalid if it expires within the refresh buffer
	return time.Now().Before(token.RefreshAt)
}

// ShouldRefreshOAuthToken checks if the token should be refreshed
func ShouldRefreshOAuthToken() bool {
	token, err := LoadOAuthToken()
	if err != nil {
		return false
	}

	return time.Now().After(token.RefreshAt) && time.Now().Before(token.ExpiresAt)
}

// RefreshOAuthAccessToken refreshes the access token using the refresh token
func RefreshOAuthAccessToken(refreshToken, authServiceURL, clientID string) (*TokenResponse, error) {
	if refreshToken == "" {
		return nil, fmt.Errorf("refresh token is empty")
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.PostForm(authServiceURL+"/token", data)
	if err != nil {
		return nil, fmt.Errorf("failed to make refresh request: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("refresh failed: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	// If no new refresh token provided, keep the old one
	if tokenResp.RefreshToken == "" {
		tokenResp.RefreshToken = refreshToken
	}

	return &tokenResp, nil
}

// GetValidOAuthToken returns a valid access token, refreshing if necessary
func GetValidOAuthToken(authServiceURL, clientID string) (string, error) {
	// Check if we have a valid token
	if IsOAuthTokenValid() {
		token, err := LoadOAuthToken()
		if err == nil {
			return token.AccessToken, nil
		}
	}

	// Check if we should refresh
	if ShouldRefreshOAuthToken() {
		token, err := LoadOAuthToken()
		if err != nil {
			return "", fmt.Errorf("no token available for refresh, please run 'shush login'")
		}

		// Try to refresh the token
		refreshed, err := RefreshOAuthAccessToken(token.RefreshToken, authServiceURL, clientID)
		if err != nil {
			return "", fmt.Errorf("token refresh failed, please run 'shush login': %w", err)
		}

		// Save the refreshed token
		if err := SaveOAuthToken(refreshed); err != nil {
			// Log warning but still return the token
			fmt.Printf("Warning: failed to save refreshed token: %v\n", err)
		}

		return refreshed.AccessToken, nil
	}

	return "", fmt.Errorf("no valid token available, please run 'shush login'")
}

// SecureOAuthTokenWipe attempts to securely overwrite token data
func SecureOAuthTokenWipe() error {
	tokenMutex.Lock()
	defer tokenMutex.Unlock()

	cacheFile, err := getOAuthTokenCacheFile()
	if err != nil {
		return err
	}

	// Get file info to determine size
	info, err := os.Stat(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, nothing to wipe
		}
		return err
	}

	// Open file for writing
	file, err := os.OpenFile(cacheFile, os.O_WRONLY, 0600)
	if err != nil {
		return err
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
			return fmt.Errorf("failed to overwrite file: %w", err)
		}

		if err := file.Sync(); err != nil {
			return fmt.Errorf("failed to sync file: %w", err)
		}
	}

	file.Close()

	// Finally remove the file
	return os.Remove(cacheFile)
}

// GetOAuthTokenInfo returns information about the current token without exposing sensitive data
func GetOAuthTokenInfo() (*OAuthTokenInfo, error) {
	token, err := LoadOAuthToken()
	if err != nil {
		return nil, err
	}

	return &OAuthTokenInfo{
		IsValid:   IsOAuthTokenValid(),
		ExpiresAt: token.ExpiresAt,
		IssuedAt:  token.IssuedAt,
		TokenType: token.TokenType,
	}, nil
}

// OAuthTokenInfo provides non-sensitive token information
type OAuthTokenInfo struct {
	IsValid   bool      `json:"is_valid"`
	ExpiresAt time.Time `json:"expires_at"`
	IssuedAt  time.Time `json:"issued_at"`
	TokenType string    `json:"token_type"`
}
