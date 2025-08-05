package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/patchware-org/shush/internal/config"
)

// Token represents a standardized token structure
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	TokenType    string    `json:"token_type,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	IssuedAt     time.Time `json:"issued_at"`
}

// getTokenCacheFile returns the path to the token cache file
func getTokenCacheFile() (string, error) {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, config.TokenCacheFile), nil
}

// SaveToken saves the token to the file system
func SaveToken(tokenResp *TokenResponse) error {
	cacheFile, err := getTokenCacheFile()
	if err != nil {
		return err
	}

	configDir, err := config.GetConfigDir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	now := time.Now()
	token := &Token{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		IDToken:      tokenResp.IDToken,
		TokenType:    tokenResp.TokenType,
		ExpiresAt:    now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		IssuedAt:     now,
	}

	file, err := os.Create(cacheFile)
	if err != nil {
		return fmt.Errorf("failed to create token cache file: %w", err)
	}
	defer file.Close()

	// Set restrictive permissions on the token file (best-effort on Windows)
	if err := file.Chmod(0600); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("failed to set file permissions: %w", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(token); err != nil {
		return fmt.Errorf("failed to encode token: %w", err)
	}

	return nil
}

// LoadToken loads the cached token from the file system
func LoadToken() (*Token, error) {
	cacheFile, err := getTokenCacheFile()
	if err != nil {
		return nil, err
	}

	file, err := os.Open(cacheFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open token cache file: %w", err)
	}
	defer file.Close()

	var token Token
	if err := json.NewDecoder(file).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	return &token, nil
}

// RemoveToken deletes the cached token file
func RemoveToken() error {
	cacheFile, err := getTokenCacheFile()
	if err != nil {
		return err
	}

	if err := os.Remove(cacheFile); err != nil {
		return fmt.Errorf("failed to remove token cache file: %w", err)
	}
	return nil
}

// IsTokenValid checks if the cached token exists and is not expired
func IsTokenValid() bool {
	token, err := LoadToken()
	if err != nil {
		return false
	}

	// Consider token invalid if it expires within 5 minutes
	return time.Now().Add(5 * time.Minute).Before(token.ExpiresAt)
}

// RefreshAccessToken refreshes the access token using the refresh token
func RefreshAccessToken(refreshToken, authServiceURL, clientID string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)

	resp, err := http.PostForm(authServiceURL+"/token", data)
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

	return &tokenResp, nil
}

// GetValidToken returns a valid access token, refreshing if necessary
func GetValidToken(authServiceURL, clientID string) (string, error) {
	// Check if we have a valid token
	if IsTokenValid() {
		token, err := LoadToken()
		if err == nil {
			return token.AccessToken, nil
		}
	}

	// Try to load token and refresh if needed
	token, err := LoadToken()
	if err != nil {
		return "", fmt.Errorf("no valid token available, please run 'login' command")
	}

	// Try to refresh the token
	refreshed, err := RefreshAccessToken(token.RefreshToken, authServiceURL, clientID)
	if err != nil {
		return "", fmt.Errorf("token refresh failed, please run 'login' command: %w", err)
	}

	// Save the refreshed token
	if err := SaveToken(refreshed); err != nil {
		// Log warning but still return the token
		fmt.Printf("Warning: failed to save refreshed token: %v\n", err)
	}

	return refreshed.AccessToken, nil
}
