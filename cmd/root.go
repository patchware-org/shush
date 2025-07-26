/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
)

// Configuration for authentication
var (
	ZitadelIssuer  string
	AuthServiceURL string
	ClientID       string
	Scope          string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "shush",
	Short: "Secure, developer-first secrets management from the command line.",
	Long: `shush is a local-first, end-to-end encrypted secrets manager built for developers
who live in the terminal. It makes managing secrets across teams, environments, and
infrastructure effortless — without dashboards, vendor lock-in, or security theater.

shush encrypts your secrets locally, syncs them through a secure backend, and decrypts
them only for the users and environments you authorize.

Start with 'shush init' to begin managing secrets in your current project.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.shush.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.

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

	// Validate required configuration (excluding AUTH_PROVIDER, as it’s command-specific)
	if ZitadelIssuer == "" || AuthServiceURL == "" || ClientID == "" || Scope == "" {
		fmt.Println("Error: Missing required configuration in .env file (ZITADEL_ISSUER, AUTH_SERVICE_URL, CLIENT_ID, SCOPE)")
		os.Exit(1)
	}

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
