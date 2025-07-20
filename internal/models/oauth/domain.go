package oauth

import (
	"time"

	"github.com/google/uuid"
)

type OAuth2Client struct {
	ID                      uuid.UUID `json:"id" db:"id"`
	TenantID                uuid.UUID `json:"tenant_id" db:"tenant_id"`
	ClientID                string    `json:"client_id" db:"client_id"`
	ClientSecret            string    `json:"-" db:"client_secret_hash"`
	Name                    string    `json:"name" db:"name"`
	Description             string    `json:"description" db:"description"`
	RedirectURIs            []string  `json:"redirect_uris" db:"redirect_uris"`
	Scopes                  []string  `json:"scopes" db:"scopes"`
	GrantTypes              []string  `json:"grant_types" db:"grant_types"`
	ResponseTypes           []string  `json:"response_types" db:"response_types"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method" db:"token_endpoint_auth_method"`
	IsPublic                bool      `json:"is_public" db:"is_public"`
	IsActive                bool      `json:"is_active" db:"is_active"`
	AccessTokenLifetime     int       `json:"access_token_lifetime" db:"access_token_lifetime"`
	RefreshTokenLifetime    int       `json:"refresh_token_lifetime" db:"refresh_token_lifetime"`
	CreatedAt               time.Time `json:"created_at" db:"created_at"`
	UpdatedAt               time.Time `json:"updated_at" db:"updated_at"`
}

type AuthorizationCode struct {
	ID                  uuid.UUID `json:"id" db:"id"`
	TenantID            uuid.UUID `json:"tenant_id" db:"tenant_id"`
	ClientID            uuid.UUID `json:"client_id" db:"client_id"`
	UserID              uuid.UUID `json:"user_id" db:"user_id"`
	Code                string    `json:"code" db:"code_hash"`
	CodeChallenge       string    `json:"-" db:"code_challenge"`
	CodeChallengeMethod string    `json:"-" db:"code_challenge_method"`
	RedirectURI         string    `json:"redirect_uri" db:"redirect_uri"`
	Scopes              []string  `json:"scopes" db:"scopes"`
	State               string    `json:"state" db:"state"`
	Nonce               string    `json:"nonce" db:"nonce"`
	Used                bool      `json:"used" db:"used"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
	ExpiresAt           time.Time `json:"expires_at" db:"expires_at"`
}
