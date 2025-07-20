package user

import (
	"time"

	"github.com/google/uuid"
)

type SecurityEventType string

const (
	SecurityEventTypeLoginSuccess SecurityEventType = "login_success"
	SecurityEventTypeLoginFailure SecurityEventType = "login_failure"
	SecurityEventTypeLogout       SecurityEventType = "logout"
)

type CreateUserCommand struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	Username     string
	Email        string
	PasswordHash string
	Enabled      bool
	CreatedBy    uuid.UUID
	CreatedAt    time.Time
}

type UpdateUserCommand struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Username  *string
	Email     *string
	Enabled   *bool
	UpdatedBy uuid.UUID
	UpdatedAt time.Time
}

type ChangeUserPasswordCommand struct {
	ID           uuid.UUID
	TenantID     uuid.UUID
	PasswordHash string
	UpdatedBy    uuid.UUID
	UpdatedAt    time.Time
}

type DeleteUserCommand struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	DeletedBy uuid.UUID
	DeletedAt time.Time
}

type RevokeAllUserTokensCommand struct {
	UserID    uuid.UUID
	TenantID  uuid.UUID
	RevokedAt time.Time
	RevokedBy uuid.UUID
	Reason    string
}

type CreateSessionCommand struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	UserID    uuid.UUID
	IPAddress string
	UserAgent string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type LogSecurityEventCommand struct {
	ID         uuid.UUID
	TenantID   uuid.UUID
	UserID     *uuid.UUID
	EventType  SecurityEventType
	IPAddress  string
	UserAgent  string
	Details    map[string]any
	OccurredAt time.Time
}

type CleanupExpiredTokensCommand struct {
	TenantID  *uuid.UUID // nil for all tenants
	Before    time.Time
	BatchSize int
}

type UpdateUserLastLoginCommand struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	LastLoginAt time.Time
}
