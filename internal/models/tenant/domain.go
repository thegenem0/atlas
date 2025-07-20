package tenant

import (
	"time"

	"github.com/google/uuid"
	"github.com/thegenem0/atlas/internal/models/shared"
)

type Tenant struct {
	ID        uuid.UUID    `json:"id" db:"id"`
	Name      string       `json:"name" db:"name"`
	Domain    string       `json:"domain" db:"domain"`
	Slug      string       `json:"slug" db:"slug"`
	Settings  shared.JSONB `json:"settings" db:"settings"`
	IsActive  bool         `json:"is_active" db:"is_active"`
	CreatedAt time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt time.Time    `json:"updated_at" db:"updated_at"`
}

