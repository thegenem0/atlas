package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/thegenem0/atlas/internal/database"
	"github.com/thegenem0/atlas/internal/models/auth"
	"github.com/thegenem0/atlas/internal/models/oauth"
	"github.com/thegenem0/atlas/internal/models/user"
	"golang.org/x/crypto/bcrypt"
)

type authService struct {
	db           database.IDatabase
	tokenService ITokenService
	logger       zerolog.Logger
}

func NewAuthService(db database.IDatabase, tokenService ITokenService, logger zerolog.Logger) IAuthService {
	return &authService{
		db:           db,
		tokenService: tokenService,
		logger:       logger,
	}
}

// ChangePassword implements IAuthService.
func (a *authService) ChangePassword(ctx context.Context, userID uuid.UUID, currentPassword string, newPassword string) error {
	panic("unimplemented")
}

// ConfirmPasswordReset implements IAuthService.
func (a *authService) ConfirmPasswordReset(ctx context.Context, token string, newPassword string) error {
	panic("unimplemented")
}

// Login implements IAuthService.
func (a *authService) Login(ctx context.Context, tenantID uuid.UUID, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	tenantID := appctx.GetTenantIDFromContext(ctx)
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("tenant not found in context")
	}

	failedAttempts, err := a.db.GetFailedLoginAttempts(ctx, tenantID, req.Email, time.Now().Add(-time.Hour))
	if err != nil {
		a.logger.Error().Err(err).Msg("Failed to get failed login attempts")
	} else if failedAttempts >= 5 {
		return nil, fmt.Errorf("too many failed login attempts, please try again later")
	}

	creds, err := a.db.GetUserCredentials(ctx, tenantID, req.Email)
	if err != nil {
		a.logSecurityEvent(ctx, auth.SecurityEventLoginFailed, nil, map[string]interface{}{
			"email":  req.Email,
			"reason": "user_not_found",
		})
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(req.Password)); err != nil {
		a.logSecurityEvent(ctx, auth.SecurityEventLoginFailed, &creds.ID, map[string]interface{}{
			"email":  req.Email,
			"reason": "invalid_password",
		})
		return nil, fmt.Errorf("invalid credentials")

	}

	if !creds.IsActive {
		return nil, fmt.Errorf("account is inactive")
	}

	if creds.IsLocked && (creds.LockedUntil == nil || time.Now().Before(*creds.LockedUntil)) {
		return nil, fmt.Errorf("account is locked")
	}

	sessionID := uuid.New()
	sessionCmd := &user.CreateSessionCommand{
		ID:        sessionID,
		TenantID:  creds.TenantID,
		UserID:    creds.ID,
		IPAddress: appctx.GetIPFromContext(ctx),
		UserAgent: appctx.GetUserAgentFromContext(ctx),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := a.db.CreateSession(ctx, sessionCmd); err != nil {
		a.logger.Error().Err(err).Msg("Failed to create session")
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	defaultClient, err := a.getDefaultClient(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get default client: %w", err)
	}

	user := a.credsToUserReadModel(creds)

	defaultScopes := []string{"openid", "profile", "email"}

	accessTokenID := uuid.New()
	accessToken, err := a.tokenService.GenerateAccessToken(ctx, user, defaultClient, defaultScopes, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := a.tokenService.GenerateRefreshToken(ctx, user, defaultClient, defaultScopes, sessionID, accessTokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	updateLoginCmd := &user.UpdateUserLastLoginCommand{
		ID:          creds.ID,
		TenantID:    creds.TenantID,
		LastLoginAt: time.Now(),
	}

	if err := a.db.UpdateUserLastLogin(ctx, updateLoginCmd); err != nil {
		a.logger.Error().Err(err).Msg("Failed to update last login")
		// NOTE(thegenem0): Don't fail the login just for this
	}

	a.logSecurityEvent(ctx, auth.SecurityEventLoginSuccess, &creds.ID, map[string]interface{}{
		"email":      req.Email,
		"session_id": sessionID.String(),
	})

	a.logger.Info().
		Str("user_id", creds.ID.String()).
		Str("email", req.Email).
		Str("session_id", sessionID.String()).
		Msg("User logged in successfully")

	return &auth.LoginResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		TokenType:        "Bearer",
		ExpiresIn:        int(15 * 60),          // 15 minutes
		RefreshExpiresIn: int(7 * 24 * 60 * 60), // 7 days
		User:             a.userReadModelToDomain(user),
		SessionID:        sessionID.String(),
	}, nil

}

// Logout implements IAuthService.
func (a *authService) Logout(ctx context.Context, sessionID uuid.UUID) error {
	panic("unimplemented")
}

// LogoutAll implements IAuthService.
func (a *authService) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	panic("unimplemented")
}

// RefreshToken implements IAuthService.
func (a *authService) RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*auth.LoginResponse, error) {
	panic("unimplemented")
}

// ResetPassword implements IAuthService.
func (a *authService) ResetPassword(ctx context.Context, tenantID uuid.UUID, email string) error {
	panic("unimplemented")
}

// RevokeToken implements IAuthService.
func (a *authService) RevokeToken(ctx context.Context, token string) error {
	panic("unimplemented")
}

// SendEmailVerification implements IAuthService.
func (a *authService) SendEmailVerification(ctx context.Context, userID uuid.UUID) error {
	panic("unimplemented")
}

// ValidateToken implements IAuthService.
func (a *authService) ValidateToken(ctx context.Context, token string) (*auth.JWTClaims, error) {
	panic("unimplemented")
}

// VerifyEmail implements IAuthService.
func (a *authService) VerifyEmail(ctx context.Context, token string) error {
	panic("unimplemented")
}

func (a *authService) getDefaultClient(ctx context.Context, tenantID uuid.UUID) (*oauth.OAuth2ClientReadModel, error) {
	clients, err := a.db.ListOAuth2Clients(ctx, tenantID, oauth.ClientFilter{
		Limit: 1,
	})
	if err != nil {
		return nil, err
	}

	if len(clients) == 0 {
		return nil, fmt.Errorf("no OAuth2 clients found for tenant")
	}

	return clients[0], nil
}

func (a *authService) credsToUserReadModel(creds *user.UserCredentials) *user.UserReadModel {
	return &user.UserReadModel{
		ID:        creds.ID,
		TenantID:  creds.TenantID,
		Email:     creds.Email,
		IsActive:  creds.IsActive,
		CreatedAt: creds.CreatedAt,
	}
}
