package auth

import (
	"time"

	"github.com/google/uuid"
)

type StoreAccessTokenCommand struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	ClientID  uuid.UUID
	UserID    uuid.UUID
	SessionID uuid.UUID
	TokenHash string
	Scopes    []string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type StoreRefreshTokenCommand struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	ClientID      uuid.UUID
	UserID        uuid.UUID
	SessionID     uuid.UUID
	TokenHash     string
	AccessTokenID uuid.UUID
	Scopes        []string
	ExpiresAt     time.Time
	Used          bool
	CreatedAt     time.Time
}

type MarkRefreshTokenAsUsedCommand struct {
	ID     uuid.UUID
	UsedAt time.Time
}

type RevokeAccessTokenCommand struct {
	ID        uuid.UUID
	RevokedAt time.Time
	RevokedBy uuid.UUID // User who revoked it
	Reason    string
}

type RevokeAllUserTokensCommand struct {
	UserID    uuid.UUID
	RevokedAt time.Time
	RevokedBy uuid.UUID // User who revoked it
	Reason    string
}
