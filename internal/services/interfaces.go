package services

import (
	"context"
	"os/user"

	"github.com/google/uuid"
	"github.com/thegenem0/atlas/internal/models/auth"
	"github.com/thegenem0/atlas/internal/models/oauth"
)

type IAuthService interface {
	// Password-based authentication
	Login(ctx context.Context, tenantID uuid.UUID, req *auth.LoginRequest) (*auth.LoginResponse, error)
	Logout(ctx context.Context, sessionID uuid.UUID) error
	LogoutAll(ctx context.Context, userID uuid.UUID) error

	// Token operations
	RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.LoginResponse, error)
	ValidateToken(ctx context.Context, token string) (*auth.JWTClaims, error)
	RevokeToken(ctx context.Context, token string) error

	// User operations
	ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword, newPassword string) error
	ResetPassword(ctx context.Context, tenantID uuid.UUID, email string) error
	ConfirmPasswordReset(ctx context.Context, token, newPassword string) error

	// Email verification
	SendEmailVerification(ctx context.Context, userID uuid.UUID) error
	VerifyEmail(ctx context.Context, token string) error
}

// type IOAuth2Service interface {
// 	// Authorization Code Flow
// 	Authorize(ctx context.Context, tenantID uuid.UUID, req *models.OAuth2AuthorizeRequest) (string, error)
// 	Token(ctx context.Context, tenantID uuid.UUID, req *models.OAuth2TokenRequest) (*models.OAuth2TokenResponse, error)
//
// 	// Client Credentials Flow
// 	ClientCredentials(ctx context.Context, tenantID uuid.UUID, clientID, clientSecret string, scopes []string) (*models.OAuth2TokenResponse, error)
//
// 	// Resource Owner Password Flow
// 	ResourceOwnerPassword(ctx context.Context, tenantID uuid.UUID, clientID, clientSecret, username, password string, scopes []string) (*models.OAuth2TokenResponse, error)
//
// 	// Token introspection
// 	IntrospectToken(ctx context.Context, token string) (map[string]interface{}, error)
//
// 	// OIDC
// 	UserInfo(ctx context.Context, token string) (*models.UserInfoResponse, error)
// 	GetDiscovery(ctx context.Context, tenantID uuid.UUID) (*models.OIDCDiscovery, error)
// 	GetJWKS(ctx context.Context, tenantID uuid.UUID) (interface{}, error)
// }

type ITokenService interface {
	// JWT operations
	GenerateAccessToken(ctx context.Context, user *user.User, client *oauth.OAuth2Client, scopes []string, sessionID uuid.UUID) (string, error)
	GenerateRefreshToken(ctx context.Context, user *user.User, client *oauth.OAuth2Client, scopes []string, sessionID uuid.UUID, accessTokenID uuid.UUID) (string, error)
	GenerateIDToken(ctx context.Context, user *user.User, client *oauth.OAuth2Client, nonce string, sessionID uuid.UUID) (string, error)

	// Token validation
	ValidateJWT(ctx context.Context, tokenString string) (*auth.JWTClaims, error)
	ValidateAccessToken(ctx context.Context, tokenString string) (*auth.AccessToken, error)
	ValidateRefreshToken(ctx context.Context, tokenString string) (*auth.RefreshToken, error)

	// Token storage
	StoreAccessToken(ctx context.Context, token *auth.AccessToken) error
	StoreRefreshToken(ctx context.Context, token *auth.RefreshToken) error
	RevokeAccessToken(ctx context.Context, tokenID uuid.UUID) error
	RevokeRefreshToken(ctx context.Context, tokenID uuid.UUID) error

	// Cleanup
	CleanupExpiredTokens(ctx context.Context) error
}

// type IClientService interface {
// 	// Client management
// 	CreateClient(ctx context.Context, tenantID uuid.UUID, client *models.OAuth2Client) (*models.OAuth2Client, error)
// 	GetClient(ctx context.Context, tenantID uuid.UUID, clientID string) (*models.OAuth2Client, error)
// 	UpdateClient(ctx context.Context, tenantID uuid.UUID, clientID string, updates map[string]interface{}) (*models.OAuth2Client, error)
// 	DeleteClient(ctx context.Context, tenantID uuid.UUID, clientID string) error
// 	ListClients(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.OAuth2Client, error)
//
// 	// Client validation
// 	ValidateClient(ctx context.Context, tenantID uuid.UUID, clientID, clientSecret string) (*models.OAuth2Client, error)
// 	ValidateRedirectURI(ctx context.Context, client *models.OAuth2Client, redirectURI string) error
// 	ValidateScopes(ctx context.Context, client *models.OAuth2Client, scopes []string) error
// 	ValidateGrantType(ctx context.Context, client *models.OAuth2Client, grantType string) error
// }
//
// type ISessionService interface {
// 	// Session management
// 	CreateSession(ctx context.Context, user *models.User, clientID *uuid.UUID, metadata map[string]interface{}) (*models.Session, error)
// 	GetSession(ctx context.Context, sessionID uuid.UUID) (*models.Session, error)
// 	UpdateSession(ctx context.Context, sessionID uuid.UUID, updates map[string]interface{}) error
// 	DeleteSession(ctx context.Context, sessionID uuid.UUID) error
// 	DeleteUserSessions(ctx context.Context, userID uuid.UUID) error
//
// 	// Session validation
// 	ValidateSession(ctx context.Context, sessionID uuid.UUID) (*models.Session, error)
// 	RefreshSession(ctx context.Context, sessionID uuid.UUID) error
//
// 	// Session cleanup
// 	CleanupExpiredSessions(ctx context.Context) error
// }
//
// type IUserService interface {
// 	// User management
// 	CreateUser(ctx context.Context, tenantID uuid.UUID, user *models.User) (*models.User, error)
// 	GetUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) (*models.User, error)
// 	GetUserByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*models.User, error)
// 	GetUserByUsername(ctx context.Context, tenantID uuid.UUID, username string) (*models.User, error)
// 	UpdateUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID, updates map[string]interface{}) (*models.User, error)
// 	DeleteUser(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) error
// 	ListUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*models.User, error)
//
// 	// Password management
// 	ValidatePassword(ctx context.Context, user *models.User, password string) error
// 	HashPassword(ctx context.Context, password string) (string, error)
//
// 	// Email verification
// 	CreateEmailVerificationToken(ctx context.Context, userID uuid.UUID) (*models.EmailVerificationToken, error)
// 	ValidateEmailVerificationToken(ctx context.Context, token string) (*models.EmailVerificationToken, error)
//
// 	// Password reset
// 	CreatePasswordResetToken(ctx context.Context, userID uuid.UUID) (*models.PasswordResetToken, error)
// 	ValidatePasswordResetToken(ctx context.Context, token string) (*models.PasswordResetToken, error)
// }
//
// type ITenantService interface {
// 	// Tenant management
// 	CreateTenant(ctx context.Context, tenant *models.Tenant) (*models.Tenant, error)
// 	GetTenant(ctx context.Context, tenantID uuid.UUID) (*models.Tenant, error)
// 	GetTenantByDomain(ctx context.Context, domain string) (*models.Tenant, error)
// 	GetTenantBySlug(ctx context.Context, slug string) (*models.Tenant, error)
// 	UpdateTenant(ctx context.Context, tenantID uuid.UUID, updates map[string]interface{}) (*models.Tenant, error)
// 	DeleteTenant(ctx context.Context, tenantID uuid.UUID) error
// 	ListTenants(ctx context.Context, limit, offset int) ([]*models.Tenant, error)
//
// 	// Tenant resolution
// 	ResolveTenantFromRequest(ctx context.Context, host, path string) (*models.Tenant, error)
// }
