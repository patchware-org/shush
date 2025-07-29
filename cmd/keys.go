/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/patchware-org/shush/internal/crypto"
	"github.com/spf13/cobra"
)

// keysCmd represents the keys command
var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Manage your encryption keys",
	Long: `Manage your local encryption keys used for end-to-end encryption.
These keys are automatically generated during login and are used to encrypt
your secrets before they are stored or transmitted.`,
}

// keysStatusCmd shows the status of encryption keys
var keysStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of your encryption keys",
	Long:  `Display whether encryption keys exist and show the public key for sharing.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := showKeysStatus(); err != nil {
			fmt.Printf("Failed to check key status: %v\n", err)
			os.Exit(1)
		}
	},
}

// keysGenerateCmd generates new encryption keys
var keysGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate new encryption keys",
	Long:  `Generate a new pair of encryption keys, replacing any existing keys.`,
	Run: func(cmd *cobra.Command, args []string) {
		force, _ := cmd.Flags().GetBool("force")
		if err := generateKeys(force); err != nil {
			fmt.Printf("Failed to generate keys: %v\n", err)
			os.Exit(1)
		}
	},
}

// // keysRemoveCmd removes encryption keys
// var keysRemoveCmd = &cobra.Command{
// 	Use:   "remove",
// 	Short: "Remove encryption keys",
// 	Long: `Remove your local encryption keys.
// Warning: This will make any existing encrypted data inaccessible.`,
// 	Run: func(cmd *cobra.Command, args []string) {
// 		force, _ := cmd.Flags().GetBool("force")
// 		if err := removeKeys(force); err != nil {
// 			fmt.Printf("Failed to remove keys: %v\n", err)
// 			os.Exit(1)
// 		}
// 	},
// }

func init() {
	rootCmd.AddCommand(keysCmd)
	keysCmd.AddCommand(keysStatusCmd)
	keysCmd.AddCommand(keysGenerateCmd)
	// keysCmd.AddCommand(keysRemoveCmd)

	// Add force flags
	keysGenerateCmd.Flags().BoolP("force", "f", false, "Force key generation without confirmation")
	// keysRemoveCmd.Flags().BoolP("force", "f", false, "Force key removal without confirmation")
}

// showKeysStatus displays the current status of encryption keys
func showKeysStatus() error {
	if !crypto.KeyPairExists() {
		fmt.Println("Status: No encryption keys found")
		fmt.Println("Run 'shush login' or 'shush keys generate' to create keys")
		return nil
	}

	keyPair, err := crypto.LoadKeyPair()
	if err != nil {
		return fmt.Errorf("keys exist but failed to load: %w", err)
	}

	fmt.Println("Status: Encryption keys are present")
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(keyPair.GetPublicKeyBytes()))
	fmt.Println("\nYour public key can be safely shared with others to enable encrypted communication.")

	return nil
}

// generateKeys creates new encryption keys
func generateKeys(force bool) error {
	if crypto.KeyPairExists() && !force {
		fmt.Println("Encryption keys already exist.")
		fmt.Println("Generating new keys will make existing encrypted data inaccessible.")
		fmt.Print("Are you sure you want to continue? (y/N): ")

		var response string
		fmt.Scanln(&response)
		if strings.ToLower(response) != "y" {
			fmt.Println("Key generation cancelled.")
			return nil
		}
	}

	fmt.Println("Generating new encryption keys...")
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	if err := crypto.SaveKeyPair(keyPair); err != nil {
		return fmt.Errorf("failed to save key pair: %w", err)
	}

	fmt.Println("Encryption keys generated successfully!")
	fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(keyPair.GetPublicKeyBytes()))

	return nil
}

// removeKeys deletes the encryption keys
func removeKeys(force bool) error {
	if !crypto.KeyPairExists() {
		fmt.Println("No encryption keys found to remove.")
		return nil
	}

	if !force {
		fmt.Println("This will remove your encryption keys and make encrypted data inaccessible.")
		fmt.Print("Are you sure you want to continue? (y/N): ")

		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Key removal cancelled.")
			return nil
		}
	}

	if err := crypto.RemoveKeyPair(); err != nil {
		return fmt.Errorf("failed to remove keys: %w", err)
	}

	fmt.Println("Encryption keys removed successfully.")
	return nil
}
