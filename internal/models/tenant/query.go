package tenant

import (
	"time"

	"github.com/google/uuid"
)

type TenantReadModel struct {
	ID          uuid.UUID `db:"id"`
	Name        string    `db:"name"`
	DisplayName string    `db:"display_name"`
	Enabled     bool      `db:"enabled"`
	UserCount   int       `db:"user_count"` // Denormalized
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

type TenantFilter struct {
	Enabled *bool
	Limit   int
	Offset  int
}
