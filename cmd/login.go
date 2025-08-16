package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/patchware-org/shush/internal/auth"
	"github.com/patchware-org/shush/internal/crypto"
	"github.com/patchware-org/shush/internal/models"
	"github.com/patchware-org/shush/utils/config"
	"github.com/spf13/cobra"
)

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
	},
}

func init() {
	rootCmd.AddCommand(loginCmd)
}

// LoginRollback manages rollback of login artifacts
type LoginRollback struct {
	manager *auth.RollbackManager
}

// NewLoginRollback creates a new login rollback manager
func NewLoginRollback() *LoginRollback {
	return &LoginRollback{
		manager: auth.NewRollbackManager(true), // verbose = true
	}
}

// AddOAuthToken marks OAuth token for rollback
func (lr *LoginRollback) AddOAuthToken() {
	lr.manager.AddOAuthTokenRollback()
}

// AddKeyPair marks key pair for rollback
func (lr *LoginRollback) AddKeyPair() {
	lr.manager.AddKeyPairRollback()
}

// AddBackendToken marks backend token for rollback
func (lr *LoginRollback) AddBackendToken() {
	lr.manager.AddBackendTokenRollback()
}

// Execute performs the rollback
func (lr *LoginRollback) Execute() {
	fmt.Println("Login failed. Rolling back changes...")
	if err := lr.manager.Execute(); err != nil {
		fmt.Printf("Rollback failed: %v\n", err)
		fmt.Println("You may need to manually clean up authentication files")
	}
}

// performDeviceAuth implements the OAuth2 device authorization flow with rollback
func performDeviceAuth() error {
	rollback := NewLoginRollback()

	// Check if user is already logged in with a valid token
	if auth.IsOAuthTokenValid() {
		fmt.Println("You are already logged in with a valid token.")
		return nil
	}

	// Check if we have an expired token that can be refreshed
	if existingToken, err := auth.LoadOAuthToken(); err == nil && existingToken.RefreshToken != "" {
		fmt.Println("Existing token is expired. Attempting to refresh...")

		cfg, err := config.LoadConfig()
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		refreshed, err := auth.RefreshOAuthAccessToken(existingToken.RefreshToken, cfg.AuthServiceURL, cfg.ClientID)
		if err == nil {
			// Save the refreshed token
			if err := auth.SaveOAuthToken(refreshed); err != nil {
				fmt.Printf("Warning: failed to save refreshed token: %v\n", err)
			} else {
				fmt.Println("Token refreshed successfully!")
				return nil
			}
		}
		fmt.Printf("Token refresh failed (%v). Proceeding with new authentication...\n", err)
	}

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Validate required configuration
	if cfg.AuthProvider == "" {
		return fmt.Errorf("missing required configuration: AUTH_PROVIDER")
	}
	if cfg.AuthProvider != "zitadel" {
		return fmt.Errorf("unsupported auth provider: %s", cfg.AuthProvider)
	}

	// Create auth configuration
	authConfig := &auth.AuthConfig{
		Issuer:         cfg.ZitadelIssuer,
		AuthServiceURL: cfg.AuthServiceURL,
		ClientID:       cfg.ClientID,
		Scope:          cfg.Scope,
	}

	// Step 1: Request device and user codes
	deviceResp, err := auth.GetDeviceCode(authConfig)
	if err != nil {
		return fmt.Errorf("failed to request device code: %w", err)
	}

	// Display user instructions
	fmt.Printf("To authenticate, please visit: %s\n", deviceResp.VerificationURI)
	fmt.Printf("Enter this code: %s\n", deviceResp.UserCode)
	if deviceResp.VerificationURIComplete != "" {
		fmt.Printf("Or visit this complete URL: %s\n", deviceResp.VerificationURIComplete)
	}
	fmt.Println("Waiting for you to complete authentication...")

	// Step 2: Poll for token
	token, err := auth.PollForToken(authConfig, deviceResp.DeviceCode, deviceResp.Interval, deviceResp.ExpiresIn)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Step 3: Save OAuth token to cache
	if err := auth.SaveOAuthToken(token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}
	rollback.AddOAuthToken()
	fmt.Println("✓ OAuth token saved")

	// Step 4: Generate or ensure key pair exists for E2E encryption
	keyPairGenerated, err := ensureKeyPairWithState()
	if err != nil {
		rollback.Execute()
		return fmt.Errorf("failed to setup encryption keys: %w", err)
	}
	if keyPairGenerated {
		rollback.AddKeyPair()
		fmt.Println("✓ Encryption keys generated")
	}

	// Step 5: Register device with backend
	if err := registerDeviceWithBackend(token, cfg, rollback); err != nil {
		rollback.Execute()
		return fmt.Errorf("failed to register device with backend: %w", err)
	}

	fmt.Println("Successfully authenticated!")
	return nil
}

// ensureKeyPairWithState generates a new key pair if one doesn't exist and returns whether it was generated
func ensureKeyPairWithState() (bool, error) {
	if crypto.KeyPairExists() {
		fmt.Println("Encryption keys already exist.")
		return false, nil
	}

	fmt.Println("Generating encryption keys for secure communication...")
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return false, fmt.Errorf("failed to generate key pair: %w", err)
	}

	if err := crypto.SaveKeyPair(keyPair); err != nil {
		return false, fmt.Errorf("failed to save key pair: %w", err)
	}

	return true, nil
}

func registerDeviceWithBackend(oauthToken *auth.TokenResponse, cfg *config.Config, rollback *LoginRollback) error {
	// Load the key pair
	keyPair, err := crypto.LoadKeyPair()
	if err != nil {
		return fmt.Errorf("failed to load key pair: %w", err)
	}

	// Get device identifier
	deviceID, err := getDeviceIdentifier()
	if err != nil {
		return fmt.Errorf("failed to get device identifier: %w", err)
	}

	// Prepare registration request with properly encoded public key
	publicKeyBytes := keyPair.GetPublicKeyBytes()
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	req := models.DeviceRegistrationRequest{
		DeviceIdentifier: deviceID,
		PublicKey:        publicKeyB64, // Ensure it's base64 encoded
		IDToken:          oauthToken.IDToken,
		RefreshToken:     oauthToken.RefreshToken,
	}

	// Send registration request to backend
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Post(
		cfg.BackendURL+"/api/v1/auth/device/login",
		"application/json",
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return fmt.Errorf("failed to send registration request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body := make([]byte, 1024)
		n, _ := resp.Body.Read(body)
		return fmt.Errorf("backend registration failed with status %d: %s", resp.StatusCode, string(body[:n]))
	}

	var regResp models.DeviceRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return fmt.Errorf("failed to decode registration response: %w", err)
	}

	// Save the backend access token for future API calls
	if err := saveBackendToken(regResp.AccessToken, regResp.DeviceID); err != nil {
		return fmt.Errorf("failed to save backend token: %w", err)
	}
	rollback.AddBackendToken()
	fmt.Println("✓ Backend token saved")

	fmt.Printf("Device registered successfully. Device ID: %d\n", regResp.DeviceID)
	fmt.Printf("Welcome, %s!\n", regResp.User.Email)
	return nil
}

// Generate a unique device identifier with better sanitization
func getDeviceIdentifier() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}

	// Sanitize hostname to remove any problematic characters
	hostname = sanitizeString(hostname)

	// Get user info
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME") // Windows
	}
	if user == "" {
		user = "unknown"
	}

	// Sanitize user to remove any problematic characters
	user = sanitizeString(user)

	// Create a clean device identifier
	deviceID := fmt.Sprintf("%s-%s-%s", hostname, user, runtime.GOOS)
	return sanitizeString(deviceID), nil
}

// sanitizeString removes null bytes and other problematic characters
func sanitizeString(s string) string {
	// Remove null bytes and other control characters
	result := strings.Map(func(r rune) rune {
		// Keep alphanumeric, hyphens, underscores, dots
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return -1 // Remove the character
	}, s)

	// Ensure it's not empty
	if result == "" {
		result = "unknown"
	}

	return result
}

// Save backend-specific token and device info
func saveBackendToken(accessToken string, deviceID int64) error {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return err
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
