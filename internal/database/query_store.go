package database

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	"github.com/thegenem0/atlas/internal/models"
)

type queryStore struct {
	db     *sqlx.DB
	driver string
}

func NewQueryStore(db *sqlx.DB, driver string) IQueryStore {
	return &queryStore{db: db, driver: driver}
}

func (qs *queryStore) GetTenantByID(ctx context.Context, id uuid.UUID) (*models.TenantReadModel, error) {
	query := qs.rebind(`
        SELECT t.id, t.name, t.display_name, t.enabled, t.created_at, t.updated_at,
               COALESCE(u.user_count, 0) as user_count
        FROM tenants t
        LEFT JOIN (
            SELECT tenant_id, COUNT(*) as user_count 
            FROM users 
            WHERE enabled = true 
            GROUP BY tenant_id
        ) u ON t.id = u.tenant_id
        WHERE t.id = ?
    `)

	var tenant models.TenantReadModel
	err := qs.db.GetContext(ctx, &tenant, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrTenantNotFound
		}
		return nil, errors.Wrap(err, "failed to get tenant")
	}

	return &tenant, nil
}

func (qs *queryStore) GetUserCredentials(ctx context.Context, tenantID uuid.UUID, username string) (*models.UserCredentials, error) {
	// Optimized query for authentication - includes tenant enabled check
	query := qs.rebind(`
        SELECT u.id, u.tenant_id, u.username, u.email, u.password_hash, u.enabled,
               t.enabled as tenant_enabled
        FROM users u
        JOIN tenants t ON u.tenant_id = t.id
        WHERE u.tenant_id = ? AND u.username = ?
    `)

	var creds models.UserCredentials
	err := qs.db.GetContext(ctx, &creds, query, tenantID, username)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, errors.Wrap(err, "failed to get user credentials")
	}

	return &creds, nil
}

func (qs *queryStore) GetUserWithRoles(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) (*models.UserWithRoles, error) {
	// Get user
	user, err := qs.GetUserByID(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	// Get roles
	roles, err := qs.GetUserRoles(ctx, tenantID, userID)
	if err != nil {
		return nil, err
	}

	return &models.UserWithRoles{
		User:  user,
		Roles: roles,
	}, nil
}

func (qs *queryStore) SearchUsers(ctx context.Context, tenantID uuid.UUID, query string, limit int) ([]*models.UserSearchResult, error) {
	searchQuery := qs.rebind(`
        SELECT id, username, email, enabled
        FROM users
        WHERE tenant_id = ? 
        AND (username ILIKE ? OR email ILIKE ?)
        AND enabled = true
        ORDER BY username
        LIMIT ?
    `)

	searchTerm := "%" + query + "%"
	var users []*models.UserSearchResult

	err := qs.db.SelectContext(ctx, &users, searchQuery, tenantID, searchTerm, searchTerm, limit)
	if err != nil {
		return nil, errors.Wrap(err, "failed to search users")
	}

	return users, nil
}

func (qs *queryStore) ListUsers(ctx context.Context, tenantID uuid.UUID, filter models.UserFilter) ([]*models.UserReadModel, error) {
	query := `
        SELECT u.id, u.tenant_id, u.username, u.email, u.enabled, u.created_at, u.updated_at,
               COALESCE(r.role_count, 0) as role_count
        FROM users u
        LEFT JOIN (
            SELECT user_id, COUNT(*) as role_count 
            FROM user_roles 
            GROUP BY user_id
        ) r ON u.id = r.user_id
        WHERE u.tenant_id = ?
    `

	args := []interface{}{tenantID}

	if filter.Enabled != nil {
		query += " AND u.enabled = ?"
		args = append(args, *filter.Enabled)
	}

	if filter.Search != "" {
		query += " AND (u.username ILIKE ? OR u.email ILIKE ?)"
		searchTerm := "%" + filter.Search + "%"
		args = append(args, searchTerm, searchTerm)
	}

	query += " ORDER BY u.username"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	query = qs.rebind(query)

	var users []*models.UserReadModel
	err := qs.db.SelectContext(ctx, &users, query, args...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list users")
	}

	return users, nil
}

// GetRoleByName implements QueryStore.
func (qs *queryStore) GetRoleByName(ctx context.Context, tenantID uuid.UUID, name string) (*models.RoleReadModel, error) {
	panic("unimplemented")
}

// GetTenantByName implements QueryStore.
func (qs *queryStore) GetTenantByName(ctx context.Context, name string) (*models.TenantReadModel, error) {
	panic("unimplemented")
}

// GetUserByEmail implements QueryStore.
func (qs *queryStore) GetUserByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.UserReadModel, error) {
	panic("unimplemented")
}

// GetUserByID implements QueryStore.
func (qs *queryStore) GetUserByID(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) (*models.UserReadModel, error) {
	panic("unimplemented")
}

// GetUserByUsername implements QueryStore.
func (qs *queryStore) GetUserByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.UserReadModel, error) {
	panic("unimplemented")
}

// GetUserRoles implements QueryStore.
func (qs *queryStore) GetUserRoles(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]*models.RoleReadModel, error) {
	panic("unimplemented")
}

// ListTenants implements QueryStore.
func (qs *queryStore) ListTenants(ctx context.Context, filter models.TenantFilter) ([]*models.TenantReadModel, error) {
	panic("unimplemented")
}

func (qs *queryStore) rebind(query string) string {
	return sqlx.Rebind(sqlx.BindType(qs.driver), query)
}
