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
	confDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}

	cacheDir := filepath.Join(confDir, "shush")
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

	// Set restrictive permissions on the token file (best-effort on Windows)
	if err := file.Chmod(0600); err != nil && runtime.GOOS != "windows" {
		return err
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(cache)
}

// LoadTokenCache loads the cached token if it exists
func LoadTokenCache() (*TokenCache, error) {
	confDir, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}

	cacheFile := filepath.Join(confDir, "shush", "token_cache.json")
	file, err := os.Open(cacheFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cache TokenCache
	if err := json.NewDecoder(file).Decode(&cache); err != nil {
		return nil, err
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
	cache, _ := LoadTokenCache()
	if cache != nil {
		// If token is still valid, return it
		if time.Now().Add(5 * time.Minute).Before(cache.ExpiresAt) {
			return cache.AccessToken, nil
		}

		// Try to refresh
		refreshed, err := RefreshAccessToken(cache.RefreshToken, authServiceURL, clientID)
		if err == nil {
			_ = SaveTokenCache(refreshed)
			return refreshed.AccessToken, nil
		}
	}

	return "", fmt.Errorf("no valid token available, please run 'login' command")
}

// RemoveTokenCache deletes the cached token file
func RemoveTokenCache() error {
	confDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}

	cacheFile := filepath.Join(confDir, "shush", "token_cache.json")
	return os.Remove(cacheFile)
}
