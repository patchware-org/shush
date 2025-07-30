/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/patchware-org/shush/internal/auth"
	"github.com/patchware-org/shush/internal/crypto"
	"github.com/spf13/cobra"
)

// logoutCmd represents the logout command
var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out and revoke your session token",
	Long: `Deletes your local authentication token and ends your current session.
You must log in again to push, pull, or access remote secrets.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := performLogout(); err != nil {
			fmt.Printf("Logout failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Successfully logged out!")
	},
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}

// performLogout removes the cached token and encryption keys
func performLogout() error {
	// Remove authentication token
	if err := auth.RemoveToken(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("you are not currently logged in")
		}
		return fmt.Errorf("failed to remove authentication token: %w", err)
	}

	// Remove encryption keys
	if err := crypto.RemoveKeyPair(); err != nil {
		// Log warning but don't fail logout if keys can't be removed
		fmt.Printf("Warning: failed to remove encryption keys: %v\n", err)
	}

	return nil
}
