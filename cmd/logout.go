// File: cmd/logout.go
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/patchware-org/shush/internal/auth"
	"github.com/patchware-org/shush/internal/models"
	"github.com/spf13/cobra"
)

var (
	forceLogout    bool
	skipRemote     bool
	secureWipe     bool
	removeKeysFlag bool
)

// logoutCmd represents the logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out and revoke your session token",
	Long: `Deletes your local authentication token and ends your current session by calling the backend logout API.
You must log in again to push, pull, or access remote secrets.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := performLogout(); err != nil {
			if forceLogout {
				fmt.Printf("Warning: %v\n", err)
				fmt.Println("Forcing local logout...")
				if err := forceLocalLogout(); err != nil {
					fmt.Printf("Force logout failed: %v\n", err)
					os.Exit(1)
				}
			} else {
				fmt.Printf("Logout failed: %v\n", err)
				fmt.Println("Use --force to logout locally even if remote logout fails")
				os.Exit(1)
			}
		}
		fmt.Println("Successfully logged out!")
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
	logoutCmd.Flags().BoolVar(&forceLogout, "force", false, "Force logout even if backend is unreachable")
	logoutCmd.Flags().BoolVar(&skipRemote, "local-only", false, "Only logout locally, skip backend call")
	logoutCmd.Flags().BoolVar(&secureWipe, "secure-wipe", false, "Securely overwrite token files before deletion")
	logoutCmd.Flags().BoolVar(&removeKeysFlag, "remove-keys", false, "Also remove encryption keys (WARNING: this will require re-authentication for all devices)")
}

// performLogout calls the backend logout API and removes local token and encryption keys
func performLogout() error {
	// Check authentication status first
	authStatus := auth.GetAuthenticationStatus()

	if !authStatus.HasBackendToken && !authStatus.HasValidOAuthToken {
		fmt.Println("You are not currently logged in.")
		return nil
	}

	fmt.Printf("Current authentication status:\n")
	fmt.Printf("  OAuth token: %v\n", authStatus.HasValidOAuthToken)
	fmt.Printf("  Backend token: %v\n", authStatus.HasBackendToken)
	fmt.Printf("  Encryption keys: %v\n", authStatus.HasKeyPair)
	fmt.Println()

	// Load backend token for remote logout
	var backendToken *models.BackendAuth
	var err error

	if authStatus.HasBackendToken {
		backendToken, err = auth.LoadBackendToken()
		if err != nil {
			return fmt.Errorf("failed to load backend token: %w", err)
		}
	}

	// Skip remote logout if requested or if we don't have a backend token
	if !skipRemote && backendToken != nil {
		fmt.Println("Logging out from backend...")
		if err := callBackendLogout(backendToken.AccessToken, backendToken.DeviceID); err != nil {
			return fmt.Errorf("backend logout failed: %w", err)
		}
		fmt.Println("✓ Backend logout successful")
	} else if skipRemote {
		fmt.Println("Skipping backend logout (local-only mode)")
	}

	// Always perform local cleanup
	fmt.Println("Cleaning up local authentication data...")
	return performLocalCleanup()
}

// callBackendLogout calls the backend logout API
func callBackendLogout(accessToken string, deviceID int64) error {
	// Get backend URL from environment or config
	backendURL := os.Getenv("SHUSH_BACKEND_URL")
	if backendURL == "" {
		backendURL = "http://localhost:8080" // default for development
	}

	logoutURL := backendURL + "/api/v1/auth/device/logout"

	// Create request with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Include device_id in request body
	reqBody, err := json.Marshal(struct {
		DeviceID int64 `json:"device_id"`
	}{DeviceID: deviceID})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", logoutURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create logout request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		// Check if it's a network/timeout error
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("logout request timed out - backend may be unreachable")
		}
		return fmt.Errorf("failed to send logout request: %w", err)
	}
	defer resp.Body.Close()

	// Handle different response codes
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized:
		// Token already invalid, that's fine
		fmt.Println("Note: token was already invalid on backend")
		return nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("logout API returned status %d: %s", resp.StatusCode, string(body))
	}
}

// performLocalCleanup removes local tokens and keys using the new cleanup utilities
func performLocalCleanup() error {
	var result *auth.CleanupResult

	if secureWipe {
		fmt.Println("Performing secure wipe of authentication data...")
		result = auth.PerformSecureCleanup(removeKeysFlag)
	} else {
		fmt.Println("Removing authentication data...")
		result = auth.PerformCompleteCleanup(removeKeysFlag)
	}

	// Print the cleanup summary
	fmt.Print(result.String())

	// Return error if there were any critical failures
	if len(result.Errors) > 0 {
		// Check if these are just "file not found" type errors
		criticalErrors := make([]string, 0)
		for _, errMsg := range result.Errors {
			// Only consider it critical if it's not about missing files
			if !strings.Contains(errMsg, "no such file") && !strings.Contains(errMsg, "cannot find") {
				criticalErrors = append(criticalErrors, errMsg)
			}
		}

		if len(criticalErrors) > 0 {
			return fmt.Errorf("cleanup completed with errors: %v", criticalErrors)
		}
	}

	return nil
}

// forceLocalLogout performs only local cleanup, ignoring most errors
func forceLocalLogout() error {
	fmt.Println("Forcing local cleanup...")

	var result *auth.CleanupResult
	if secureWipe {
		result = auth.PerformSecureCleanup(true) // Force remove keys in force mode
	} else {
		result = auth.PerformCompleteCleanup(true) // Force remove keys in force mode
	}

	// Print the cleanup summary
	fmt.Print(result.String())

	// In force mode, we don't return errors - just warn about them
	if len(result.Errors) > 0 {
		fmt.Println("Some cleanup operations failed, but continuing due to --force flag")
	}

	return nil
}
