package role

import (
	"time"

	"github.com/google/uuid"
)

type CreateRoleCommand struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Name        string
	Description string
	CreatedBy   uuid.UUID
	CreatedAt   time.Time
}

type AssignRoleCommand struct {
	UserID     uuid.UUID
	RoleID     uuid.UUID
	TenantID   uuid.UUID
	AssignedBy uuid.UUID
	AssignedAt time.Time
}
