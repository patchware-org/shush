/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/patchware-org/shush/internal/auth"
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

// performLogout removes the cached token file
func performLogout() error {
	// Try to remove the token cache
	if err := auth.RemoveTokenCache(); err != nil {
		// If the error is because the file doesn't exist, that's okay
		if os.IsNotExist(err) {
			return fmt.Errorf("you are not currently logged in")
		}
		return fmt.Errorf("failed to remove token cache: %w", err)
	}

	return nil
}
