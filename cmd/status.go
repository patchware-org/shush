package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/patchware-org/shush/internal/auth"
	"github.com/spf13/cobra"
)

var (
	statusJSON bool
)

// statusCmd represents the status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show authentication status",
	Long:  `Displays the current authentication status including token validity and available credentials.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := showAuthStatus(); err != nil {
			fmt.Printf("Failed to get status: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
	statusCmd.Flags().BoolVar(&statusJSON, "json", false, "Output status in JSON format")
}

// showAuthStatus displays the current authentication status
func showAuthStatus() error {
	status := auth.GetAuthenticationStatus()

	if statusJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(status)
	}

	// Human-readable output
	fmt.Println("Authentication Status:")
	fmt.Println("======================")

	if status.IsFullyLoggedIn {
		fmt.Println("Fully authenticated and ready to use")
	} else {
		fmt.Println("Not fully authenticated")
	}

	fmt.Println()
	fmt.Println("Components:")

	// OAuth Token
	if status.HasValidOAuthToken {
		fmt.Println("  OAuth Token: Valid")
		if status.OAuthTokenInfo != nil {
			fmt.Printf("     Expires: %s\n", status.OAuthTokenInfo.ExpiresAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("     Type: %s\n", status.OAuthTokenInfo.TokenType)
		}
	} else {
		fmt.Println("  OAuth Token: Invalid or missing")
	}

	// Backend Token
	if status.HasBackendToken {
		fmt.Println("  Backend Token: Present")
	} else {
		fmt.Println("  Backend Token: Missing")
	}

	// Encryption Keys
	if status.HasKeyPair {
		fmt.Println("  Encryption Keys: Present")
	} else {
		fmt.Println("  Encryption Keys: Missing")
	}

	fmt.Println()

	// Recommendations
	if !status.IsFullyLoggedIn {
		fmt.Println("Recommendations:")
		if !status.HasValidOAuthToken {
			fmt.Println("  • Run 'shush login' to authenticate")
		}
		if !status.HasBackendToken {
			fmt.Println("  • Run 'shush login' to register with backend")
		}
		if !status.HasKeyPair {
			fmt.Println("  • Run 'shush login' to generate encryption keys")
		}
	} else {
		fmt.Println("You're all set! You can now use shush to manage secrets.")
	}

	return nil
}
