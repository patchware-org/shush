package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/patchware-org/shush/internal/auth"
	"github.com/patchware-org/shush/utils/config"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	token      string
	deviceID   int64
	userID     int64
}

type BackendAuth struct {
	AccessToken string `json:"access_token"`
	DeviceID    int64  `json:"device_id"`
	UserID      int64  `json:"user_id"`
}

type APIError struct {
	StatusCode int    `json:"-"`
	ErrorMsg   string `json:"error"`
	Message    string `json:"message,omitempty"`
	Code       string `json:"code,omitempty"`
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("API error (%d): %s - %s", e.StatusCode, e.ErrorMsg, e.Message)
	}
	return fmt.Sprintf("API error (%d): %s", e.StatusCode, e.ErrorMsg)
}

// NewClient creates a new API client
func NewClient() (*Client, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	client := &Client{
		baseURL: cfg.BackendURL,
		httpClient: &http.Client{
			Timeout: time.Duration(cfg.DefaultTimeout) * time.Second,
		},
	}

	// Try to load existing backend token
	if err := client.loadBackendAuth(); err != nil {
		// This is OK, user might not be logged in yet
	}

	return client, nil
}

// loadBackendAuth loads the backend authentication from cache
func (c *Client) loadBackendAuth() error {
	configDir, err := config.GetConfigDir()
	if err != nil {
		return err
	}

	authFile := filepath.Join(configDir, config.BackendTokenFile)
	file, err := os.Open(authFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var auth BackendAuth
	if err := json.NewDecoder(file).Decode(&auth); err != nil {
		return err
	}

	c.token = auth.AccessToken
	c.deviceID = auth.DeviceID
	c.userID = auth.UserID
	return nil
}

// RefreshAuthIfNeeded checks if auth is still valid and refreshes if needed
func (c *Client) RefreshAuthIfNeeded() error {
	if !c.IsAuthenticated() {
		return fmt.Errorf("not authenticated")
	}

	// Try to get a fresh token from auth package
	cfg, err := config.LoadConfig()
	if err != nil {
		return err
	}

	token, err := auth.GetValidOAuthToken(cfg.AuthServiceURL, cfg.ClientID)
	if err != nil {
		return fmt.Errorf("failed to refresh authentication: %w", err)
	}

	// Update our stored backend token if needed
	if token != c.token && token != "" {
		// Token was refreshed, we should re-authenticate with backend
		// This might require re-running the device login flow
		return fmt.Errorf("authentication expired, please run 'shush login' again")
	}

	return nil
}

// SetAuth sets the authentication token and device ID
func (c *Client) SetAuth(token string, deviceID, userID int64) {
	c.token = token
	c.deviceID = deviceID
	c.userID = userID
}

// IsAuthenticated checks if the client has valid authentication
func (c *Client) IsAuthenticated() bool {
	return c.token != "" && c.deviceID != 0
}

// request makes an authenticated HTTP request with retry logic
func (c *Client) request(method, path string, body interface{}) (*http.Response, error) {
	return c.requestWithContext(context.Background(), method, path, body)
}

// requestWithContext makes an authenticated HTTP request with context
func (c *Client) requestWithContext(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Add authentication if available
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	// Handle authentication errors
	if resp.StatusCode == http.StatusUnauthorized {
		// Try to refresh auth once
		if err := c.RefreshAuthIfNeeded(); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("authentication failed: %w", err)
		}

		// Retry the request once with new auth
		resp.Body.Close()
		return c.requestWithContext(ctx, method, path, body)
	}

	return resp, nil
}

// handleAPIError processes API error responses
func (c *Client) handleAPIError(resp *http.Response) error {
	var apiErr APIError
	apiErr.StatusCode = resp.StatusCode

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("HTTP %d: failed to read error response", resp.StatusCode)
	}

	if err := json.Unmarshal(body, &apiErr); err != nil {
		// Fallback to plain text error
		apiErr.ErrorMsg = string(body)
	}

	return &apiErr
}

// GET makes a GET request
func (c *Client) GET(path string) (*http.Response, error) {
	return c.request("GET", path, nil)
}

// POST makes a POST request
func (c *Client) POST(path string, body interface{}) (*http.Response, error) {
	return c.request("POST", path, body)
}

// PUT makes a PUT request
func (c *Client) PUT(path string, body interface{}) (*http.Response, error) {
	return c.request("PUT", path, body)
}

// DELETE makes a DELETE request
func (c *Client) DELETE(path string) (*http.Response, error) {
	return c.request("DELETE", path, nil)
}

// Logout calls the backend logout endpoint
func (c *Client) Logout() error {
	if !c.IsAuthenticated() {
		return fmt.Errorf("not authenticated")
	}

	resp, err := c.POST("/api/v1/auth/device/logout", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.handleAPIError(resp)
	}

	// Clear local auth
	c.token = ""
	c.deviceID = 0
	c.userID = 0

	return nil
}

// GetProjects fetches user's projects
func (c *Client) GetProjects() ([]Project, error) {
	if !c.IsAuthenticated() {
		return nil, fmt.Errorf("not authenticated")
	}

	resp, err := c.GET(fmt.Sprintf("/api/v1/users/%d/projects", c.userID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleAPIError(resp)
	}

	var projects []Project
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, fmt.Errorf("failed to decode projects: %w", err)
	}

	return projects, nil
}

// Project represents a project
type Project struct {
	ID        int64     `json:"id"`
	OwnerID   int64     `json:"owner_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
