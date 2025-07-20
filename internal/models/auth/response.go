package auth

import "github.com/thegenem0/atlas/internal/models/user"

type LoginResponse struct {
	AccessToken      string     `json:"access_token"`
	RefreshToken     string     `json:"refresh_token,omitempty"`
	TokenType        string     `json:"token_type"`
	ExpiresIn        int        `json:"expires_in"`
	RefreshExpiresIn int        `json:"refresh_expires_in,omitempty"`
	Scope            string     `json:"scope,omitempty"`
	User             *user.User `json:"user"`
	SessionID        string     `json:"session_id"`
}

type UserInfoResponse struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	Picture           string `json:"picture,omitempty"`
	UpdatedAt         int64  `json:"updated_at"`
}
