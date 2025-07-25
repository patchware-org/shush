package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthProvider defines the interface for authentication providers
type AuthProvider interface {
	GetDeviceCode() (*DeviceAuthResponse, error)
	PollForToken(deviceCode string, interval, expiresIn int) (*TokenResponse, error)
}

// DeviceAuthResponse represents the response from the device authorization endpoint
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// TokenResponse represents the token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Error        string `json:"error,omitempty"`
	ErrorDesc    string `json:"error_description,omitempty"`
}

// ZitadelAuthProvider implements the AuthProvider interface for Zitadel
type ZitadelAuthProvider struct {
	Issuer         string
	AuthServiceURL string
	ClientID       string
	Scope          string
}

func (z *ZitadelAuthProvider) GetDeviceCode() (*DeviceAuthResponse, error) {
	// Discovery document fetching
	discoveryURL := z.Issuer + "/.well-known/openid-configuration"
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discovery endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var discovery struct {
		DeviceAuthEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	deviceAuthEndpoint := z.AuthServiceURL + "/device_authorization"
	if discovery.DeviceAuthEndpoint != "" {
		deviceAuthEndpoint = discovery.DeviceAuthEndpoint
	}

	data := url.Values{}
	data.Set("client_id", z.ClientID)
	data.Set("scope", z.Scope)

	req, err := http.NewRequest("POST", deviceAuthEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err = client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errorResp) == nil {
			return nil, fmt.Errorf("device authorization failed (%d): %s - %s",
				resp.StatusCode, errorResp.Error, errorResp.ErrorDescription)
		}
		return nil, fmt.Errorf("device authorization failed (%d): %s", resp.StatusCode, string(body))
	}

	var deviceResp DeviceAuthResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, fmt.Errorf("failed to parse device response: %w", err)
	}

	return &deviceResp, nil
}

func (z *ZitadelAuthProvider) PollForToken(deviceCode string, interval, expiresIn int) (*TokenResponse, error) {
	// Discovery document fetching
	discoveryURL := z.Issuer + "/.well-known/openid-configuration"
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discovery endpoint returned status %d: %s", resp.StatusCode, string(body))
	}

	var discovery struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	tokenEndpoint := z.AuthServiceURL + "/token"
	if discovery.TokenEndpoint != "" {
		tokenEndpoint = discovery.TokenEndpoint
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(expiresIn)*time.Second)
	defer cancel()

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("authentication timeout")
		case <-ticker.C:
			data := url.Values{}
			data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			data.Set("device_code", deviceCode)
			data.Set("client_id", z.ClientID)

			resp, err := http.PostForm(tokenEndpoint, data)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()

			var tokenResp TokenResponse
			if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
				return nil, err
			}

			switch tokenResp.Error {
			case "":
				return &tokenResp, nil
			case "authorization_pending":
				continue
			case "slow_down":
				ticker.Reset(time.Duration(interval+5) * time.Second)
				continue
			case "expired_token":
				return nil, fmt.Errorf("device code expired")
			case "access_denied":
				return nil, fmt.Errorf("user denied access")
			default:
				return nil, fmt.Errorf("authentication error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
			}
		}
	}
}
