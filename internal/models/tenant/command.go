package tenant

import (
	"time"

	"github.com/google/uuid"
)

type CreateTenantCommand struct {
	ID          uuid.UUID
	Name        string
	DisplayName string
	Enabled     bool
	CreatedBy   uuid.UUID
	CreatedAt   time.Time
}

type UpdateTenantCommand struct {
	ID          uuid.UUID
	DisplayName *string
	Enabled     *bool
	UpdatedBy   uuid.UUID
	UpdatedAt   time.Time
}

type DeleteTenantCommand struct {
	ID        uuid.UUID
	DeletedBy uuid.UUID
	DeletedAt time.Time
}
