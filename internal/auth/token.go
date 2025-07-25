package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// TokenCache represents the stored token information
type TokenCache struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SaveTokenCache saves the token to a local cache file
func SaveTokenCache(token *TokenResponse) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	cacheDir := filepath.Join(homeDir, ".shush")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return err
	}

	cache := TokenCache{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      token.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second),
	}

	cacheFile := filepath.Join(cacheDir, "token_cache.json")
	file, err := os.Create(cacheFile)
	if err != nil {
		return err
	}
	defer file.Close()

	// Set restrictive permissions on the token file
	if err := file.Chmod(0600); err != nil {
		return err
	}

	return json.NewEncoder(file).Encode(cache)
}

// LoadTokenCache loads the cached token if it exists and is valid
func LoadTokenCache() (*TokenCache, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	cacheFile := filepath.Join(homeDir, ".shush", "token_cache.json")
	file, err := os.Open(cacheFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cache TokenCache
	if err := json.NewDecoder(file).Decode(&cache); err != nil {
		return nil, err
	}

	// Check if token is expired (with 5 minute buffer)
	if time.Now().Add(5 * time.Minute).After(cache.ExpiresAt) {
		return nil, fmt.Errorf("token expired")
	}

	return &cache, nil
}

// RefreshAccessToken refreshes the access token using the refresh token
func RefreshAccessToken(refreshToken, authServiceURL, clientID string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", clientID)

	resp, err := http.PostForm(authServiceURL+"/token", data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("refresh failed: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	return &tokenResp, nil
}

// GetValidToken returns a valid access token, refreshing if necessary
func GetValidToken(authServiceURL, clientID string) (string, error) {
	// Try to load cached token
	cache, err := LoadTokenCache()
	if err == nil {
		return cache.AccessToken, nil
	}

	// If cache failed but we have a refresh token, try to refresh
	if cache != nil && cache.RefreshToken != "" {
		refreshed, err := RefreshAccessToken(cache.RefreshToken, authServiceURL, clientID)
		if err == nil {
			// Save the refreshed token
			if saveErr := SaveTokenCache(refreshed); saveErr != nil {
			}
			return refreshed.AccessToken, nil
		}
	}

	return "", fmt.Errorf("no valid token available, please run 'login' command")
}
