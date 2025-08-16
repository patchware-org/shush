package models

import "time"

// User represents a user from the backend API
type User struct {
	ID            int64     `json:"id"`
	OAuthSub      string    `json:"oauth_sub"`
	Email         string    `json:"email"`
	Name          *string   `json:"name"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// DeviceRegistrationRequest for backend device registration
type DeviceRegistrationRequest struct {
	DeviceIdentifier string `json:"device_identifier"`
	PublicKey        string `json:"public_key"`
	IDToken          string `json:"id_token"`
	RefreshToken     string `json:"refresh_token"`
}

// DeviceRegistrationResponse from backend device registration
type DeviceRegistrationResponse struct {
	DeviceID    int64  `json:"device_id"`
	AccessToken string `json:"access_token"`
	User        User   `json:"user"`
}

// BackendAuth represents stored backend authentication
type BackendAuth struct {
	AccessToken string `json:"access_token"`
	DeviceID    int64  `json:"device_id"`
}

// Project represents a project from the backend
type Project struct {
	ID        int64     `json:"id"`
	OwnerID   int64     `json:"owner_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Scope represents a scope from the backend
type Scope struct {
	ID              int64     `json:"id"`
	ProjectID       int64     `json:"project_id"`
	Name            string    `json:"name"`
	SymmetricKeyEnc string    `json:"symmetric_key_enc"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Secret represents a secret from the backend
type Secret struct {
	ID        int64     `json:"id"`
	ScopeID   int64     `json:"scope_id"`
	Key       string    `json:"key"`
	ValueEnc  string    `json:"value_enc"`
	Format    string    `json:"format"`
	CreatedBy int64     `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
