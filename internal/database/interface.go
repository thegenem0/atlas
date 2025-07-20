package database

import (
	"context"

	"github.com/google/uuid"
	"github.com/thegenem0/atlas/internal/models/auth"
	"github.com/thegenem0/atlas/internal/models/oauth"
	"github.com/thegenem0/atlas/internal/models/role"
	"github.com/thegenem0/atlas/internal/models/tenant"
	"github.com/thegenem0/atlas/internal/models/user"
)

type IDatabase interface {
	ICommandStore
	IQueryStore
	Close() error
	Ping() error
	GetMigrationVersion() (uint, bool, error)
}

type ICommandStore interface {
	// Tenant commands
	CreateTenant(ctx context.Context, cmd *tenant.CreateTenantCommand) error
	UpdateTenant(ctx context.Context, cmd *tenant.UpdateTenantCommand) error
	DeleteTenant(ctx context.Context, cmd *tenant.DeleteTenantCommand) error

	// User commands
	CreateUser(ctx context.Context, cmd *user.CreateUserCommand) error
	UpdateUser(ctx context.Context, cmd *user.UpdateUserCommand) error
	DeleteUser(ctx context.Context, cmd *user.DeleteUserCommand) error
	ChangeUserPassword(ctx context.Context, cmd *user.ChangeUserPasswordCommand) error
	// VerifyUserEmail(ctx context.Context, cmd *user.VerifyUserEmailCommand) error
	UpdateUserLastLogin(ctx context.Context, cmd *user.UpdateUserLastLoginCommand) error

	// Role commands
	CreateRole(ctx context.Context, cmd *role.CreateRoleCommand) error
	// UpdateRole(ctx context.Context, cmd *role.UpdateRoleCommand) error
	// DeleteRole(ctx context.Context, cmd *role.DeleteRoleCommand) error
	AssignRole(ctx context.Context, cmd *role.AssignRoleCommand) error
	// UnassignRole(ctx context.Context, cmd *role.UnassignRoleCommand) error

	// Auth Token commands
	StoreAccessToken(ctx context.Context, cmd *auth.StoreAccessTokenCommand) error
	StoreRefreshToken(ctx context.Context, cmd *auth.StoreRefreshTokenCommand) error
	// RevokeAccessToken(ctx context.Context, cmd *auth.RevokeAccessTokenCommand) error
	// RevokeRefreshToken(ctx context.Context, cmd *auth.RevokeRefreshTokenCommand) error
	MarkRefreshTokenAsUsed(ctx context.Context, cmd *auth.MarkRefreshTokenAsUsedCommand) error
	RevokeAllUserTokens(ctx context.Context, cmd *auth.RevokeAllUserTokensCommand) error
	// RevokeAllUserSessions(ctx context.Context, cmd *auth.RevokeAllUserSessionsCommand) error

	// Session commands
	CreateSession(ctx context.Context, cmd *user.CreateSessionCommand) error
	// UpdateSession(ctx context.Context, cmd *auth.UpdateSessionCommand) error
	// EndSession(ctx context.Context, cmd *auth.EndSessionCommand) error

	// OAuth2 Client commands
	// CreateOAuth2Client(ctx context.Context, cmd *oauth.CreateOAuth2ClientCommand) error
	// UpdateOAuth2Client(ctx context.Context, cmd *oauth.UpdateOAuth2ClientCommand) error
	// DeleteOAuth2Client(ctx context.Context, cmd *oauth.DeleteOAuth2ClientCommand) error
	// RegenerateClientSecret(ctx context.Context, cmd *oauth.RegenerateClientSecretCommand) error

	// OAuth2 Flow commands
	// StoreAuthorizationCode(ctx context.Context, cmd *oauth.StoreAuthorizationCodeCommand) error
	// MarkAuthorizationCodeAsUsed(ctx context.Context, cmd *oauth.MarkAuthorizationCodeAsUsedCommand) error
	// StoreConsent(ctx context.Context, cmd *oauth.StoreConsentCommand) error
	// RevokeConsent(ctx context.Context, cmd *oauth.RevokeConsentCommand) error

	// Cleanup commands
	// CleanupExpiredTokens(ctx context.Context, cmd *auth.CleanupExpiredTokensCommand) error
	// CleanupExpiredCodes(ctx context.Context, cmd *oauth.CleanupExpiredCodesCommand) error
	// CleanupExpiredSessions(ctx context.Context, cmd *auth.CleanupExpiredSessionsCommand) error

	// Audit commands
	// LogSecurityEvent(ctx context.Context, cmd *auth.LogSecurityEventCommand) error
}

type IQueryStore interface {
	// Tenant queries
	GetTenantByID(ctx context.Context, id uuid.UUID) (*tenant.TenantReadModel, error)
	GetTenantByName(ctx context.Context, name string) (*tenant.TenantReadModel, error)
	ListTenants(ctx context.Context, filter tenant.TenantFilter) ([]*tenant.TenantReadModel, error)

	// User queries
	GetUserByID(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) (*user.UserReadModel, error)
	GetUserByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*user.UserReadModel, error)
	GetUserByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*user.UserReadModel, error)
	ListUsers(ctx context.Context, tenantID uuid.UUID, filter user.UserFilter) ([]*user.UserReadModel, error)
	// SearchUsers(ctx context.Context, tenantID uuid.UUID, query string, limit int) ([]*models.UserSearchResult, error)

	// Authentication queries (optimized for login)
	// GetUserCredentials(ctx context.Context, tenantID uuid.UUID, email string) (*auth.UserCredentials, error)
	GetUserRoles(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]*role.RoleReadModel, error)
	GetUserPermissions(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]string, error)
	// GetUserWithRoles(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) (*users.UserWithRoles, error)

	// Token queries
	// GetAccessTokenByID(ctx context.Context, id uuid.UUID) (*auth.AccessTokenReadModel, error)
	// GetRefreshTokenByID(ctx context.Context, id uuid.UUID) (*auth.RefreshTokenReadModel, error)
	// ValidateAccessToken(ctx context.Context, tokenHash string) (*auth.AccessTokenReadModel, error)
	// ValidateRefreshToken(ctx context.Context, tokenHash string) (*auth.RefreshTokenReadModel, error)
	// GetUserTokens(ctx context.Context, userID uuid.UUID) (*auth.UserTokensReadModel, error)
	// GetActiveSessionTokens(ctx context.Context, sessionID uuid.UUID) (*auth.SessionTokensReadModel, error)

	// Session queries
	// GetSessionByID(ctx context.Context, id uuid.UUID) (*auth.SessionReadModel, error)
	// GetUserSessions(ctx context.Context, userID uuid.UUID) ([]*auth.SessionReadModel, error)
	// GetActiveUserSessions(ctx context.Context, userID uuid.UUID) ([]*auth.SessionReadModel, error)

	// OAuth2 Client queries
	// GetOAuth2ClientByID(ctx context.Context, clientID string) (*oauth.OAuth2ClientReadModel, error)
	GetOAuth2ClientByTenant(ctx context.Context, tenantID uuid.UUID, clientID string) (*oauth.OAuth2ClientReadModel, error)
	ListOAuth2Clients(ctx context.Context, tenantID uuid.UUID, filter oauth.ClientFilter) ([]*oauth.OAuth2ClientReadModel, error)

	// OAuth2 Flow queries
	// GetAuthorizationCode(ctx context.Context, codeHash string) (*oauth.AuthorizationCodeReadModel, error)
	// GetUserConsents(ctx context.Context, userID uuid.UUID) ([]*oauth.ConsentReadModel, error)
	// GetClientConsents(ctx context.Context, clientID string) ([]*oauth.ConsentReadModel, error)

	// Security & Audit queries
	// GetSecurityEvents(ctx context.Context, filter auth.SecurityEventFilter) ([]*auth.SecurityEventReadModel, error)
	// GetFailedLoginAttempts(ctx context.Context, tenantID uuid.UUID, identifier string, since time.Time) (int, error)

	// Health & Stats Queries
	// GetTokenStats(ctx context.Context, tenantID uuid.UUID) (*auth.TokenStatsReadModel, error)
	// GetActiveUserCount(ctx context.Context, tenantID uuid.UUID) (int64, error)
}
