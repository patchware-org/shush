/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/go-git/go-git/v5"

	"github.com/patchware-org/shush/internal/config"
	"github.com/patchware-org/shush/internal/version"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init [project-dir]",
	Short: "Initialize shush in the current project",
	Long: `Initializes shush in the current repository by creating the config file,
generating your local encryption keys, and preparing the secrets environment.

Run this once per project to begin managing secrets with shush.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Get project directory
		projectDir := "."
		if len(args) > 0 {
			projectDir = args[0]
		}

		// Get initial scope from flag
		initialScope, _ := cmd.Flags().GetString("initial-scope")

		// Initialize the project
		if err := initializeProject(projectDir, initialScope); err != nil {
			fmt.Printf("Error initializing project: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	// Add flags
	initCmd.Flags().StringP("initial-scope", "s", "main", "defines the project initial scope name")
}


func initializeProject(projectDir, initialScope string) error {
	// Create project directory if it doesn't exist
	if err := os.MkdirAll(projectDir, 0744); err != nil {
		return fmt.Errorf("failed to create project directory: %w", err)
	}

	// Check if shush config already exists
	configDir := filepath.Join(projectDir, config.LocalConfigDir)
	configFile := filepath.Join(configDir, config.LocalConfigFile)

	if _, err := os.Stat(configFile); err == nil {
		fmt.Printf("Shush project already exists in %s\n", projectDir)
		fmt.Print("Do you want to override the existing configuration? (y/N): ")

		var response string
		fmt.Scanln(&response)
		response = strings.ToLower(strings.TrimSpace(response))

		if response != "y" && response != "yes" {
			fmt.Println("Initialization aborted.")
			return nil
		}
	}

	// Create .shush directory
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create config structure
	projectName := filepath.Base(projectDir)
	if projectName == "." {
		if cwd, err := os.Getwd(); err == nil {
			projectName = filepath.Base(cwd)
		} else {
			projectName = config.DefaultProjectName
		}
	}

	projectConfig := config.Config{
		Version:     version.Version,
		ProjectName: projectName,
		Scopes: []config.Scope{
			{
				Name:    initialScope,
				Remote:  "",
				Secrets: []config.Secret{},
			},
		},
	}

	// Write config file
	data, err := json.MarshalIndent(projectConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	_, err = git.PlainInit(configDir, false)
	if err != nil {
		return fmt.Errorf("failed to initialize git repository: %w", err)
	}

	fmt.Printf("Initialized empty shush project in %s\n", projectDir)
	return nil
}
