package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/thegenem0/atlas/internal/models/shared"
)

type AccessToken struct {
	ID        uuid.UUID  `json:"id" db:"id"`
	TenantID  uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ClientID  uuid.UUID  `json:"client_id" db:"client_id"`
	UserID    uuid.UUID  `json:"user_id" db:"user_id"`
	SessionID uuid.UUID  `json:"session_id" db:"session_id"`
	TokenHash string     `json:"-" db:"token_hash"`
	Scopes    []string   `json:"scopes" db:"scopes"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at" db:"revoked_at"`
}

type RefreshToken struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	TenantID      uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	ClientID      uuid.UUID  `json:"client_id" db:"client_id"`
	UserID        uuid.UUID  `json:"user_id" db:"user_id"`
	SessionID     uuid.UUID  `json:"session_id" db:"session_id"`
	TokenHash     string     `json:"-" db:"token_hash"`
	AccessTokenID uuid.UUID  `json:"access_token_id" db:"access_token_id"`
	Scopes        []string   `json:"scopes" db:"scopes"`
	Used          bool       `json:"used" db:"used"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at" db:"revoked_at"`
}

type JWTClaims struct {
	jwt.RegisteredClaims
	TenantID      string              `json:"tenant_id"`
	SessionID     string              `json:"session_id"`
	ClientID      string              `json:"client_id,omitempty"`
	Scopes        []string            `json:"scopes,omitempty"`
	Email         string              `json:"email"`
	Username      string              `json:"username,omitempty"`
	FirstName     string              `json:"given_name,omitempty"`
	LastName      string              `json:"family_name,omitempty"`
	EmailVerified bool                `json:"email_verified"`
	Roles         []string            `json:"roles,omitempty"`
	Permissions   []string            `json:"permissions,omitempty"`
	Metadata      map[string]any      `json:"metadata,omitempty"`
	TokenType     shared.JWTTokenType `json:"token_type"`
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	TokenType    shared.GeneratedTokenType
	ExpiresIn    int
}
