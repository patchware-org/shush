/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

// Configuration for Zitadel OAuth2
var (
	ZitadelIssuer  string
	AuthServiceURL string
	ClientID       string
	Scope          string
)

// DiscoveryResponse represents the OIDC discovery document
type DiscoveryResponse struct {
	Issuer              string   `json:"issuer"`
	AuthEndpoint        string   `json:"authorization_endpoint"`
	TokenEndpoint       string   `json:"token_endpoint"`
	DeviceAuthEndpoint  string   `json:"device_authorization_endpoint"`
	UserinfoEndpoint    string   `json:"userinfo_endpoint"`
	JwksURI             string   `json:"jwks_uri"`
	ScopesSupported     []string `json:"scopes_supported"`
	GrantTypesSupported []string `json:"grant_types_supported"`
}

// DeviceAuthResponse represents the response from the device authorization endpoint
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse represents the token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// TokenCache represents the stored token information
type TokenCache struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the shush backend",
	Long:  `Logs you into the shush backend using your credentials and fetches a JWT token to enable secure communication and key distribution.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := performDeviceAuth(); err != nil {
			fmt.Printf("Authentication failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Successfully authenticated!")
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)

	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Printf("Warning: Failed to load .env file, please ensure it exists: %v\n", err)
		os.Exit(1)
	}

	// Set configuration from environment variables
	ZitadelIssuer = os.Getenv("ZITADEL_ISSUER")
	AuthServiceURL = os.Getenv("AUTH_SERVICE_URL")
	ClientID = os.Getenv("CLIENT_ID")
	Scope = os.Getenv("SCOPE")

	// Validate required configuration
	if ZitadelIssuer == "" || AuthServiceURL == "" || ClientID == "" || Scope == "" {
		fmt.Println("Error: Missing required configuration in .env file (ZITADEL_ISSUER, AUTH_SERVICE_URL, CLIENT_ID, SCOPE)")
		os.Exit(1)
	}

	// Add flags for configuration (overridable at runtime)
	loginCmd.Flags().StringVar(&ZitadelIssuer, "issuer", ZitadelIssuer, "OIDC issuer URL")
	loginCmd.Flags().StringVar(&AuthServiceURL, "auth-service-url", AuthServiceURL, "OAuth2 auth service URL")
	loginCmd.Flags().StringVar(&ClientID, "client-id", ClientID, "OAuth2 client ID")
	loginCmd.Flags().StringVar(&Scope, "scope", Scope, "OAuth2 scopes")
}

// performDeviceAuth implements the OAuth2 device authorization flow
func performDeviceAuth() error {
	// First, let's check the discovery endpoint and get proper URLs
	discovery, err := getDiscoveryDocument()
	if err != nil {
		// No action needed if discovery fails; fall back to hardcoded endpoints
	}

	// Step 1: Request device and user codes
	deviceResp, err := requestDeviceCode(discovery)
	if err != nil {
		return fmt.Errorf("failed to request device code: %w", err)
	}

	// Step 2: Display user instructions
	fmt.Printf("To authenticate, please visit: %s\n", deviceResp.VerificationURI)
	fmt.Printf("Enter this code: %s\n", deviceResp.UserCode)
	if deviceResp.VerificationURIComplete != "" {
		fmt.Printf("Or visit this complete URL: %s\n", deviceResp.VerificationURIComplete)
	}
	fmt.Println("Waiting for you to complete authentication...")

	// Step 3: Poll for token
	token, err := pollForToken(deviceResp.DeviceCode, deviceResp.Interval, deviceResp.ExpiresIn, discovery)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Step 4: Save token to cache
	if err := saveTokenCache(token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}

// getDiscoveryDocument fetches the OIDC discovery document
func getDiscoveryDocument() (*DiscoveryResponse, error) {
	discoveryURL := ZitadelIssuer + "/.well-known/openid-configuration"
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discovery endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var discovery DiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	return &discovery, nil
}

// requestDeviceCode initiates the device authorization flow
func requestDeviceCode(discovery *DiscoveryResponse) (*DeviceAuthResponse, error) {
	// Use discovery endpoint if available, otherwise fall back to hardcoded
	deviceAuthEndpoint := AuthServiceURL + "/device_authorization"
	if discovery != nil && discovery.DeviceAuthEndpoint != "" {
		deviceAuthEndpoint = discovery.DeviceAuthEndpoint
	}

	data := url.Values{}
	data.Set("client_id", ClientID)
	data.Set("scope", Scope)

	// Create request with proper headers
	req, err := http.NewRequest("POST", deviceAuthEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse error response
		var errorResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errorResp) == nil {
			return nil, fmt.Errorf("device authorization failed (%d): %s - %s",
				resp.StatusCode, errorResp.Error, errorResp.ErrorDescription)
		}
		return nil, fmt.Errorf("device authorization failed (%d): %s", resp.StatusCode, string(body))
	}

	var deviceResp DeviceAuthResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse device response: %w", err)
	}

	return &deviceResp, nil
}

// pollForToken polls the token endpoint until the user completes authentication
func pollForToken(deviceCode string, interval, expiresIn int, discovery *DiscoveryResponse) (*TokenResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(expiresIn)*time.Second)
	defer cancel()

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("authentication timeout")
		case <-ticker.C:
			token, err := requestToken(deviceCode, discovery)
			if err != nil {
				return nil, err
			}

			switch token.Error {
			case "":
				// Success!
				return token, nil
			case "authorization_pending":
				// Still waiting for user to complete auth
				continue
			case "slow_down":
				// Increase polling interval
				ticker.Reset(time.Duration(interval+5) * time.Second)
				continue
			case "expired_token":
				return nil, fmt.Errorf("device code expired")
			case "access_denied":
				return nil, fmt.Errorf("user denied access")
			default:
				return nil, fmt.Errorf("authentication error: %s - %s", token.Error, token.ErrorDesc)
			}
		}
	}
}

// requestToken exchanges the device code for an access token
func requestToken(deviceCode string, discovery *DiscoveryResponse) (*TokenResponse, error) {
	// Use discovery endpoint if available, otherwise fall back to hardcoded
	tokenEndpoint := AuthServiceURL + "/token"
	if discovery != nil && discovery.TokenEndpoint != "" {
		tokenEndpoint = discovery.TokenEndpoint
	}

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", deviceCode)
	data.Set("client_id", ClientID)

	resp, err := http.PostForm(tokenEndpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

// saveTokenCache saves the token to a local cache file
func saveTokenCache(token *TokenResponse) error {
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
func RefreshAccessToken(refreshToken string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("client_id", ClientID)

	resp, err := http.PostForm(AuthServiceURL+"/token", data)
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
func GetValidToken() (string, error) {
	// Try to load cached token
	cache, err := LoadTokenCache()
	if err == nil {
		return cache.AccessToken, nil
	}

	// If cache failed but we have a refresh token, try to refresh
	if cache != nil && cache.RefreshToken != "" {
		refreshed, err := RefreshAccessToken(cache.RefreshToken)
		if err == nil {
			// Save the refreshed token
			if saveErr := saveTokenCache(refreshed); saveErr != nil {
			}
			return refreshed.AccessToken, nil
		}
	}

	return "", fmt.Errorf("no valid token available, please run 'login' command")
}
