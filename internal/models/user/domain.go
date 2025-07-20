package user

import (
	"time"

	"github.com/google/uuid"
	"github.com/thegenem0/atlas/internal/models/shared"
)

type User struct {
	ID                uuid.UUID    `json:"id" db:"id"`
	TenantID          uuid.UUID    `json:"tenant_id" db:"tenant_id"`
	Email             string       `json:"email" db:"email"`
	Username          *string      `json:"username" db:"username"`
	PasswordHash      string       `json:"-" db:"password_hash"`
	FirstName         *string      `json:"first_name" db:"first_name"`
	LastName          *string      `json:"last_name" db:"last_name"`
	Phone             *string      `json:"phone" db:"phone"`
	AvatarURL         *string      `json:"avatar_url" db:"avatar_url"`
	EmailVerified     bool         `json:"email_verified" db:"email_verified"`
	PhoneVerified     bool         `json:"phone_verified" db:"phone_verified"`
	IsActive          bool         `json:"is_active" db:"is_active"`
	IsAdmin           bool         `json:"is_admin" db:"is_admin"`
	LastLoginAt       *time.Time   `json:"last_login_at" db:"last_login_at"`
	PasswordChangedAt time.Time    `json:"password_changed_at" db:"password_changed_at"`
	Metadata          shared.JSONB `json:"metadata" db:"metadata"`
	CreatedAt         time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at" db:"updated_at"`
}

type Session struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	UserID           uuid.UUID  `json:"user_id" db:"user_id"`
	TenantID         uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	TokenHash        string     `json:"-" db:"token_hash"`
	RefreshTokenHash *string    `json:"-" db:"refresh_token_hash"`
	DeviceID         *string    `json:"device_id" db:"device_id"`
	UserAgent        *string    `json:"user_agent" db:"user_agent"`
	IPAddress        *string    `json:"ip_address" db:"ip_address"`
	ExpiresAt        time.Time  `json:"expires_at" db:"expires_at"`
	RefreshExpiresAt *time.Time `json:"refresh_expires_at" db:"refresh_expires_at"`
	IsActive         bool       `json:"is_active" db:"is_active"`
	LastAccessedAt   time.Time  `json:"last_accessed_at" db:"last_accessed_at"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
}
