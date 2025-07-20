package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

var (
	ErrNotFound     = errors.New("resource not found")
	ErrDuplicateKey = errors.New("duplicate key violation")
	ErrForeignKey   = errors.New("foreign key violation")
)

type Repository interface {
	WithTx(tx *sqlx.Tx) Repository
}

type TenantRepository interface {
	Repository
	Create(ctx context.Context, tenant *Tenant) error
	GetByID(ctx context.Context, id uuid.UUID) (*Tenant, error)
	GetBySlug(ctx context.Context, slug string) (*Tenant, error)
	Update(ctx context.Context, id uuid.UUID, updates map[string]any) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, filter TenantFilter) ([]*Tenant, error)
	Count(ctx context.Context, filter TenantFilter) (int64, error)
}

type UserRepository interface {
	Repository
	Create(ctx context.Context, user *User) error
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*User, error)
	Update(ctx context.Context, id uuid.UUID, updates map[string]any) error
	Delete(ctx context.Context, id uuid.UUID) error
	List(ctx context.Context, filter UserFilter) ([]*User, error)
	Count(ctx context.Context, filter UserFilter) (int64, error)
	UpdateLastLogin(ctx context.Context, id uuid.UUID, ip string) error
}

// Basic models for repositories
type Tenant struct {
	ID        uuid.UUID  `db:"id" json:"id"`
	Name      string     `db:"name" json:"name"`
	Slug      string     `db:"slug" json:"slug"`
	Domain    *string    `db:"domain" json:"domain,omitempty"`
	Settings  any        `db:"settings" json:"settings"`
	Status    string     `db:"status" json:"status"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

type User struct {
	ID                         uuid.UUID  `db:"id" json:"id"`
	TenantID                   uuid.UUID  `db:"tenant_id" json:"tenant_id"`
	Email                      string     `db:"email" json:"email"`
	EmailVerified              bool       `db:"email_verified" json:"email_verified"`
	EmailVerificationToken     *string    `db:"email_verification_token" json:"-"`
	EmailVerificationExpiresAt *time.Time `db:"email_verification_expires_at" json:"-"`
	PasswordHash               *string    `db:"password_hash" json:"-"`
	FirstName                  *string    `db:"first_name" json:"first_name,omitempty"`
	LastName                   *string    `db:"last_name" json:"last_name,omitempty"`
	Phone                      *string    `db:"phone" json:"phone,omitempty"`
	PhoneVerified              bool       `db:"phone_verified" json:"phone_verified"`
	AvatarURL                  *string    `db:"avatar_url" json:"avatar_url,omitempty"`
	Locale                     string     `db:"locale" json:"locale"`
	Timezone                   string     `db:"timezone" json:"timezone"`
	Status                     string     `db:"status" json:"status"`
	Metadata                   any        `db:"metadata" json:"metadata"`
	LastLoginAt                *time.Time `db:"last_login_at" json:"last_login_at,omitempty"`
	LastLoginIP                *string    `db:"last_login_ip" json:"-"`
	PasswordChangedAt          *time.Time `db:"password_changed_at" json:"-"`
	CreatedAt                  time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt                  time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt                  *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

type TenantFilter struct {
	Status string
	Limit  int
	Offset int
}

type UserFilter struct {
	TenantID uuid.UUID
	Status   string
	Search   string
	Limit    int
	Offset   int
}
