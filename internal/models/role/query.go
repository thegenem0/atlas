package role

import (
	"time"

	"github.com/google/uuid"
)

type RoleReadModel struct {
	ID          uuid.UUID `db:"id"`
	TenantID    uuid.UUID `db:"tenant_id"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	UserCount   int       `db:"user_count"` // Denormalized
	CreatedAt   time.Time `db:"created_at"`
}


