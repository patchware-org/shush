package cmd

import (
	"fmt"
	"os"

	"github.com/patchware-org/shush/internal/auth"
	"github.com/patchware-org/shush/internal/crypto"
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

	// loginCmd.Flags().StringVar(&ZitadelIssuer, "issuer", ZitadelIssuer, "OIDC issuer URL")
	// loginCmd.Flags().StringVar(&AuthServiceURL, "auth-service-url", AuthServiceURL, "OAuth2 auth service URL")
	// loginCmd.Flags().StringVar(&ClientID, "client-id", ClientID, "OAuth2 client ID")
	// loginCmd.Flags().StringVar(&Scope, "scope", Scope, "OAuth2 scopes")
}

// performDeviceAuth implements the OAuth2 device authorization flow
func performDeviceAuth() error {
	// Check if user is already logged in with a valid token
	if auth.IsTokenValid() {
		fmt.Println("You are already logged in with a valid token.")
		return nil
	}

	// Check if we have an expired token that can be refreshed
	if existingToken, err := auth.LoadToken(); err == nil && existingToken.RefreshToken != "" {
		fmt.Println("Existing token is expired. Attempting to refresh...")

		refreshed, err := auth.RefreshAccessToken(existingToken.RefreshToken, AuthServiceURL, ClientID)
		if err == nil {
			// Save the refreshed token
			if err := auth.SaveToken(refreshed); err != nil {
				fmt.Printf("Warning: failed to save refreshed token: %v\n", err)
			} else {
				fmt.Println("Token refreshed successfully!")
				return nil
			}
		}
		fmt.Println("Token refresh failed. Proceeding with new authentication...")
	}

	// Validate required configuration
	providerType := os.Getenv("AUTH_PROVIDER")
	if providerType == "" {
		return fmt.Errorf("missing required configuration in .env file (AUTH_PROVIDER)")
	}
	if providerType != "zitadel" {
		return fmt.Errorf("unsupported auth provider: %s", providerType)
	}

	// Create auth configuration
	config := &auth.AuthConfig{
		Issuer:         ZitadelIssuer,
		AuthServiceURL: AuthServiceURL,
		ClientID:       ClientID,
		Scope:          Scope,
	}

	// Request device and user codes
	deviceResp, err := auth.GetDeviceCode(config)
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

	// Poll for token
	token, err := auth.PollForToken(config, deviceResp.DeviceCode, deviceResp.Interval, deviceResp.ExpiresIn)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Save token to cache
	if err := auth.SaveToken(token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	// Generate or ensure key pair exists for E2E encryption
	if err := ensureKeyPair(); err != nil {
		return fmt.Errorf("failed to setup encryption keys: %w", err)
	}

	fmt.Println("Successfully authenticated!")
	return nil
}

// ensureKeyPair generates a new key pair if one doesn't exist
func ensureKeyPair() error {
	if crypto.KeyPairExists() {
		fmt.Println("Encryption keys already exist.")
		return nil
	}

	fmt.Println("Generating encryption keys for secure communication...")
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	if err := crypto.SaveKeyPair(keyPair); err != nil {
		return fmt.Errorf("failed to save key pair: %w", err)
	}

	fmt.Println("Encryption keys generated successfully.")
	return nil
}
