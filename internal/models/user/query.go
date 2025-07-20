package user

import (
	"time"

	"github.com/google/uuid"
	"github.com/thegenem0/atlas/internal/models/role"
)

type UserReadModel struct {
	ID        uuid.UUID `db:"id"`
	TenantID  uuid.UUID `db:"tenant_id"`
	Username  string    `db:"username"`
	Email     string    `db:"email"`
	IsActive  bool      `db:"is_active"`
	RoleCount int       `db:"role_count"` // Denormalized
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type UserCredentials struct {
	ID            uuid.UUID  `db:"id"`
	TenantID      uuid.UUID  `db:"tenant_id"`
	Email         string     `db:"email"`
	PasswordHash  string     `db:"password_hash"`
	EmailVerified bool       `db:"email_verified"`
	IsActive      bool       `db:"is_active"`
	IsLocked      bool       `db:"is_locked"`
	LockedUntil   *time.Time `db:"locked_until"`
	LastLoginAt   *time.Time `db:"last_login_at"`
	CreatedAt     time.Time  `db:"created_at"`
}

type UserWithRoles struct {
	User  *UserReadModel
	Roles []*role.RoleReadModel
}

type UserSearchResult struct {
	ID       uuid.UUID `db:"id"`
	Username string    `db:"username"`
	Email    string    `db:"email"`
	Enabled  bool      `db:"enabled"`
}

type SessionReadModel struct {
	ID        uuid.UUID  `db:"id"`
	TenantID  uuid.UUID  `db:"tenant_id"`
	UserID    uuid.UUID  `db:"user_id"`
	IPAddress string     `db:"ip_address"`
	UserAgent string     `db:"user_agent"`
	ExpiresAt time.Time  `db:"expires_at"`
	EndedAt   *time.Time `db:"ended_at"`
	CreatedAt time.Time  `db:"created_at"`
}

type SecurityEventFilter struct {
	TenantID   *uuid.UUID
	UserID     *uuid.UUID
	EventTypes []SecurityEventType
	IPAddress  *string
	From       *time.Time
	To         *time.Time
	Limit      int
	Offset     int
}

type UserFilter struct {
	Enabled *bool
	Limit   int
	Offset  int
	Search  string
}
