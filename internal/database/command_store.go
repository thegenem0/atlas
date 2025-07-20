package database

import (
	"context"
	"strings"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

type commandStore struct {
	db     *sqlx.DB
	driver string
}

func NewCommandStore(db *sqlx.DB, driver string) ICommandStore {
	return &commandStore{db: db, driver: driver}
}

func (cs *commandStore) CreateTenant(ctx context.Context, cmd *models.CreateTenantCommand) error {
	query := cs.rebind(`
        INSERT INTO tenants (id, name, display_name, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `)

	_, err := cs.db.ExecContext(ctx, query,
		cmd.ID, cmd.Name, cmd.DisplayName, cmd.Enabled, cmd.CreatedAt, cmd.CreatedAt,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create tenant")
	}

	// In a full CQRS system, you'd publish an event here
	// cs.eventBus.Publish(events.TenantCreated{...})

	return nil
}

func (cs *commandStore) UpdateTenant(ctx context.Context, cmd *models.UpdateTenantCommand) error {
	// Build dynamic query based on what fields are being updated
	setParts := []string{}
	args := []interface{}{}

	if cmd.DisplayName != nil {
		setParts = append(setParts, "display_name = ?")
		args = append(args, *cmd.DisplayName)
	}

	if cmd.Enabled != nil {
		setParts = append(setParts, "enabled = ?")
		args = append(args, *cmd.Enabled)
	}

	if len(setParts) == 0 {
		return errors.New("no fields to update")
	}

	setParts = append(setParts, "updated_at = ?")
	args = append(args, cmd.UpdatedAt)
	args = append(args, cmd.ID)

	query := cs.rebind(`
        UPDATE tenants 
        SET ` + strings.Join(setParts, ", ") + `
        WHERE id = ?
    `)

	result, err := cs.db.ExecContext(ctx, query, args...)
	if err != nil {
		return errors.Wrap(err, "failed to update tenant")
	}

	if rows, _ := result.RowsAffected(); rows == 0 {
		return ErrTenantNotFound
	}

	return nil
}

func (cs *commandStore) CreateUser(ctx context.Context, cmd *models.CreateUserCommand) error {
	query := cs.rebind(`
        INSERT INTO users (id, tenant_id, username, email, password_hash, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `)

	_, err := cs.db.ExecContext(ctx, query,
		cmd.ID, cmd.TenantID, cmd.Username, cmd.Email, cmd.PasswordHash,
		cmd.Enabled, cmd.CreatedAt, cmd.CreatedAt,
	)

	if err != nil {
		return errors.Wrap(err, "failed to create user")
	}

	return nil
}

// func (cs *commandStore) WithTx(ctx context.Context, fn func(context.Context, CommandStore) error) error {
// 	tx, err := cs.db.Beginx()
// 	if err != nil {
// 		return errors.Wrap(err, "failed to begin transaction")
// 	}
//
// 	txStore := &commandStore{db: tx, driver: cs.driver}
//
// 	err = fn(ctx, txStore)
// 	if err != nil {
// 		if rollbackErr := tx.Rollback(); rollbackErr != nil {
// 			return multierr.Combine(err, rollbackErr)
// 		}
// 		return err
// 	}
//
// 	if err := tx.Commit(); err != nil {
// 		return errors.Wrap(err, "failed to commit transaction")
// 	}
//
// 	return nil
// }

func (cs *commandStore) rebind(query string) string {
	return sqlx.Rebind(sqlx.BindType(cs.driver), query)
}

// AssignRole implements CommandStore.
func (cs *commandStore) AssignRole(ctx context.Context, cmd *models.AssignRoleCommand) error {
	panic("unimplemented")
}

// ChangeUserPassword implements CommandStore.
func (cs *commandStore) ChangeUserPassword(ctx context.Context, cmd *models.ChangeUserPasswordCommand) error {
	panic("unimplemented")
}

// CreateRole implements CommandStore.
func (cs *commandStore) CreateRole(ctx context.Context, cmd *models.CreateRoleCommand) error {
	panic("unimplemented")
}

// DeleteTenant implements CommandStore.
func (cs *commandStore) DeleteTenant(ctx context.Context, cmd *models.DeleteTenantCommand) error {
	panic("unimplemented")
}

// DeleteUser implements CommandStore.
func (cs *commandStore) DeleteUser(ctx context.Context, cmd *models.DeleteUserCommand) error {
	panic("unimplemented")
}

// UpdateUser implements CommandStore.
func (cs *commandStore) UpdateUser(ctx context.Context, cmd *models.UpdateUserCommand) error {
	panic("unimplemented")
}
