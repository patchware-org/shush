package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/patchware-org/shush/internal/crypto"
	"github.com/patchware-org/shush/utils/config"
)

// RollbackAction represents a single rollback action
type RollbackAction struct {
	Name          string
	Action        func() error
	CriticalError bool // If true, rollback fails if this action fails
}

// RollbackManager manages a series of rollback actions
type RollbackManager struct {
	actions []RollbackAction
	verbose bool
}

// NewRollbackManager creates a new rollback manager
func NewRollbackManager(verbose bool) *RollbackManager {
	return &RollbackManager{
		actions: make([]RollbackAction, 0),
		verbose: verbose,
	}
}

// AddAction adds a rollback action
func (rm *RollbackManager) AddAction(name string, action func() error, critical bool) {
	rm.actions = append(rm.actions, RollbackAction{
		Name:          name,
		Action:        action,
		CriticalError: critical,
	})
}

// AddOAuthTokenRollback adds OAuth token removal to rollback actions
func (rm *RollbackManager) AddOAuthTokenRollback() {
	rm.AddAction("Remove OAuth token", func() error {
		return RemoveOAuthToken()
	}, false)
}

// AddBackendTokenRollback adds backend token removal to rollback actions
func (rm *RollbackManager) AddBackendTokenRollback() {
	rm.AddAction("Remove backend token", func() error {
		return RemoveBackendToken()
	}, false)
}

// AddKeyPairRollback adds key pair removal to rollback actions
func (rm *RollbackManager) AddKeyPairRollback() {
	rm.AddAction("Remove encryption keys", func() error {
		return crypto.RemoveKeyPair()
	}, false)
}

// AddConfigDirCleanup adds config directory cleanup if it's empty
func (rm *RollbackManager) AddConfigDirCleanup() {
	rm.AddAction("Clean up empty config directory", func() error {
		configDir, err := config.GetConfigDir()
		if err != nil {
			return err
		}

		// Only remove if directory is empty
		entries, err := os.ReadDir(configDir)
		if err != nil {
			if os.IsNotExist(err) {
				return nil // Already gone
			}
			return err
		}

		if len(entries) == 0 {
			return os.Remove(configDir)
		}

		return nil // Not empty, leave it
	}, false)
}

// Execute performs all rollback actions
func (rm *RollbackManager) Execute() error {
	if len(rm.actions) == 0 {
		if rm.verbose {
			fmt.Println("No rollback actions to perform")
		}
		return nil
	}

	if rm.verbose {
		fmt.Printf("Performing rollback (%d actions)...\n", len(rm.actions))
	}

	var errors []string
	var criticalError error

	// Execute actions in reverse order (LIFO)
	for i := len(rm.actions) - 1; i >= 0; i-- {
		action := rm.actions[i]

		if rm.verbose {
			fmt.Printf("  %s...", action.Name)
		}

		if err := action.Action(); err != nil {
			if os.IsNotExist(err) {
				// File doesn't exist - this is fine for rollback
				if rm.verbose {
					fmt.Printf(" (already cleaned)\n")
				}
				continue
			}

			errMsg := fmt.Sprintf("%s failed: %v", action.Name, err)
			if action.CriticalError {
				criticalError = fmt.Errorf("critical rollback failure: %s", errMsg)
				if rm.verbose {
					fmt.Printf(" FAILED (critical)\n")
				}
				break
			} else {
				errors = append(errors, errMsg)
				if rm.verbose {
					fmt.Printf(" FAILED (non-critical)\n")
				}
			}
		} else {
			if rm.verbose {
				fmt.Printf(" ✓\n")
			}
		}
	}

	// Return critical error if one occurred
	if criticalError != nil {
		return criticalError
	}

	// Return non-critical errors as warnings
	if len(errors) > 0 {
		if rm.verbose {
			fmt.Printf("Rollback completed with %d warnings:\n", len(errors))
			for _, err := range errors {
				fmt.Printf("  - %s\n", err)
			}
		}
		// Don't return error for non-critical failures
	} else if rm.verbose {
		fmt.Println("Rollback completed successfully")
	}

	return nil
}

// SafeFileRemove safely removes a file, handling common error cases
func SafeFileRemove(filepath string) error {
	if err := os.Remove(filepath); err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, that's fine
		}
		return err
	}
	return nil
}

// SafeDirectoryRemove safely removes an empty directory
func SafeDirectoryRemove(dirpath string) error {
	if err := os.Remove(dirpath); err != nil {
		if os.IsNotExist(err) {
			return nil // Directory doesn't exist, that's fine
		}
		// Check if it failed because directory is not empty
		if entries, readErr := os.ReadDir(dirpath); readErr == nil && len(entries) > 0 {
			return nil // Directory not empty, leave it
		}
		return err
	}
	return nil
}

// CheckLoginArtifacts returns what login artifacts exist
type LoginArtifacts struct {
	OAuthTokenExists   bool
	BackendTokenExists bool
	KeyPairExists      bool
	ConfigDirExists    bool
}

// GetLoginArtifacts checks what authentication artifacts exist
func GetLoginArtifacts() *LoginArtifacts {
	configDir, _ := config.GetConfigDir()

	artifacts := &LoginArtifacts{
		OAuthTokenExists:   false,
		BackendTokenExists: false,
		KeyPairExists:      false,
		ConfigDirExists:    false,
	}

	if configDir != "" {
		if _, err := os.Stat(configDir); err == nil {
			artifacts.ConfigDirExists = true
		}

		// Check OAuth token
		oauthTokenFile := filepath.Join(configDir, config.TokenCacheFile)
		if _, err := os.Stat(oauthTokenFile); err == nil {
			artifacts.OAuthTokenExists = true
		}

		// Check backend token
		backendTokenFile := filepath.Join(configDir, config.BackendTokenFile)
		if _, err := os.Stat(backendTokenFile); err == nil {
			artifacts.BackendTokenExists = true
		}
	}

	// Check key pair
	artifacts.KeyPairExists = crypto.KeyPairExists()

	return artifacts
}
