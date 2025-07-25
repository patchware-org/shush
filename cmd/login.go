package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/patchware-org/shush/internal/auth"
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
		fmt.Println("Successfully authenticated!")
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
	// Initialize the auth provider based on configuration
	var provider auth.AuthProvider
	providerType := os.Getenv("AUTH_PROVIDER")
	if providerType == "" {
		return fmt.Errorf("missing required configuration in .env file (AUTH_PROVIDER)")
	}
	switch providerType {
	case "zitadel":
		provider = &auth.ZitadelAuthProvider{
			Issuer:         ZitadelIssuer,
			AuthServiceURL: AuthServiceURL,
			ClientID:       ClientID,
			Scope:          Scope,
		}
	default:
		return fmt.Errorf("unsupported auth provider: %s", providerType)
	}

	// Request device and user codes
	deviceResp, err := provider.GetDeviceCode()
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
	token, err := provider.PollForToken(deviceResp.DeviceCode, deviceResp.Interval, deviceResp.ExpiresIn)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	// Save token to cache
	if err := auth.SaveTokenCache(token); err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}

	return nil
}
