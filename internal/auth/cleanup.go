package auth

import (
	"fmt"
	"os"

	"github.com/patchware-org/shush/internal/crypto"
)

// CleanupResult represents the result of a cleanup operation
type CleanupResult struct {
	OAuthTokenRemoved   bool
	BackendTokenRemoved bool
	KeyPairRemoved      bool
	Errors              []string
}

// String returns a human-readable summary of the cleanup result
func (cr *CleanupResult) String() string {
	summary := "Cleanup summary:\n"

	if cr.OAuthTokenRemoved {
		summary += "  ✓ OAuth token removed\n"
	}

	if cr.BackendTokenRemoved {
		summary += "  ✓ Backend token removed\n"
	}

	if cr.KeyPairRemoved {
		summary += "  ✓ Encryption keys removed\n"
	}

	if len(cr.Errors) > 0 {
		summary += "  Warnings:\n"
		for _, err := range cr.Errors {
			summary += fmt.Sprintf("    - %s\n", err)
		}
	}

	if !cr.OAuthTokenRemoved && !cr.BackendTokenRemoved && !cr.KeyPairRemoved && len(cr.Errors) == 0 {
		summary += "  No artifacts found to remove\n"
	}

	return summary
}

// PerformCompleteCleanup removes all authentication artifacts and returns a detailed result
func PerformCompleteCleanup(includeKeys bool) *CleanupResult {
	result := &CleanupResult{}

	// Remove OAuth token
	if err := RemoveOAuthToken(); err != nil {
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to remove OAuth token: %v", err))
		}
	} else {
		result.OAuthTokenRemoved = true
	}

	// Remove backend token
	if err := RemoveBackendToken(); err != nil {
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to remove backend token: %v", err))
		}
	} else {
		result.BackendTokenRemoved = true
	}

	// Remove encryption keys if requested
	if includeKeys {
		if err := crypto.RemoveKeyPair(); err != nil {
			if !os.IsNotExist(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to remove encryption keys: %v", err))
			}
		} else {
			result.KeyPairRemoved = true
		}
	}

	return result
}

// PerformSecureCleanup performs secure wiping of sensitive data before removal
func PerformSecureCleanup(includeKeys bool) *CleanupResult {
	result := &CleanupResult{}

	// Securely wipe OAuth token
	if err := SecureOAuthTokenWipe(); err != nil {
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to securely wipe OAuth token: %v", err))
			// Try regular removal as fallback
			if err := RemoveOAuthToken(); err != nil && !os.IsNotExist(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("fallback OAuth token removal failed: %v", err))
			} else {
				result.OAuthTokenRemoved = true
			}
		}
	} else {
		result.OAuthTokenRemoved = true
	}

	// Securely wipe backend token
	if err := SecureBackendTokenWipe(); err != nil {
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("failed to securely wipe backend token: %v", err))
			// Try regular removal as fallback
			if err := RemoveBackendToken(); err != nil && !os.IsNotExist(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("fallback backend token removal failed: %v", err))
			} else {
				result.BackendTokenRemoved = true
			}
		}
	} else {
		result.BackendTokenRemoved = true
	}

	// Remove encryption keys if requested (no secure wipe implemented for keys yet)
	if includeKeys {
		if err := crypto.RemoveKeyPair(); err != nil {
			if !os.IsNotExist(err) {
				result.Errors = append(result.Errors, fmt.Sprintf("failed to remove encryption keys: %v", err))
			}
		} else {
			result.KeyPairRemoved = true
		}
	}

	return result
}

// IsLoggedIn checks if the user has valid authentication credentials
func IsLoggedIn() bool {
	// Check if we have a valid OAuth token
	if !IsOAuthTokenValid() {
		return false
	}

	// Check if we have a backend token
	if _, err := LoadBackendToken(); err != nil {
		return false
	}

	// Check if we have encryption keys
	if !crypto.KeyPairExists() {
		return false
	}

	return true
}

// GetAuthStatus returns a detailed status of the authentication state
type AuthStatus struct {
	HasValidOAuthToken bool            `json:"has_valid_oauth_token"`
	HasBackendToken    bool            `json:"has_backend_token"`
	HasKeyPair         bool            `json:"has_key_pair"`
	IsFullyLoggedIn    bool            `json:"is_fully_logged_in"`
	OAuthTokenInfo     *OAuthTokenInfo `json:"oauth_token_info,omitempty"`
}

// GetAuthenticationStatus returns comprehensive authentication status
func GetAuthenticationStatus() *AuthStatus {
	status := &AuthStatus{
		HasValidOAuthToken: IsOAuthTokenValid(),
		HasBackendToken:    BackendTokenExists(),
		HasKeyPair:         crypto.KeyPairExists(),
	}

	status.IsFullyLoggedIn = status.HasValidOAuthToken && status.HasBackendToken && status.HasKeyPair

	// Get OAuth token info if available
	if tokenInfo, err := GetOAuthTokenInfo(); err == nil {
		status.OAuthTokenInfo = tokenInfo
	}

	return status
}
