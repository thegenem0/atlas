package services

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/thegenem0/atlas/internal/database"
	"github.com/thegenem0/atlas/internal/models"
	"github.com/thegenem0/atlas/internal/models/auth"
)

type tokenService struct {
	db              database.IDatabase
	logger          zerolog.Logger
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	keyID           string
	issuer          string
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	idTokenTTL      time.Duration
}

type TokenServiceConfig struct {
	PrivateKeyPEM   string
	PublicKeyPEM    string
	KeyID           string
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	IDTokenTTL      time.Duration
}

func NewTokenService(db database.IDatabase, config *TokenServiceConfig, logger zerolog.Logger) (ITokenService, error) {
	serviceLogger := logger.With().Str("service", "token").Logger()

	privKeyBlock, _ := pem.Decode([]byte(config.PrivateKeyPEM))
	if privKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	pubKeyBlock, _ := pem.Decode([]byte(config.PublicKeyPEM))
	if pubKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	pubKeyIface, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pubKey, ok := pubKeyIface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = 15 * time.Minute
	}

	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 7 * 24 * time.Hour
	}

	if config.IDTokenTTL == 0 {
		config.IDTokenTTL = 1 * time.Hour
	}

	return &tokenService{
		db:              db,
		logger:          serviceLogger,
		privateKey:      privKey,
		publicKey:       pubKey,
		keyID:           config.KeyID,
		issuer:          config.Issuer,
		accessTokenTTL:  config.AccessTokenTTL,
		refreshTokenTTL: config.RefreshTokenTTL,
		idTokenTTL:      config.IDTokenTTL,
	}, nil

}

// GenerateAccessToken implements ITokenService.
func (t *tokenService) GenerateAccessToken(ctx context.Context, user *models.User, client *models.OAuth2Client, scopes []string, sessionID uuid.UUID) (string, error) {

	now := time.Now()
	tokenID := uuid.New()

	roles, err := t.db.GetUserRoles(ctx, user.TenantID, user.ID)
	if err != nil {
		t.logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to get user roles")
		return "", fmt.Errorf("failed to get user roles: %w", err)
	}

	permissions, err := t.db.GetUserPermissions(ctx, user.TenantID, user.ID)
	if err != nil {
		t.logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("Failed to get user permissions")
		return "", fmt.Errorf("failed to get user permissions: %w", err)
	}

	claims := &models.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID.String(),
			Subject:   user.ID.String(),
			Issuer:    t.issuer,
			Audience:  []string{client.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(t.accessTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		TenantID:      user.TenantID.String(),
		SessionID:     sessionID.String(),
		ClientID:      client.ID.String(),
		Scopes:        scopes,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Roles:         t.extractRoleNames(roles),
		Permissions:   permissions,
		TokenType:     models.JWTAccessTokenType,
	}

	if contains(scopes, "profile") {
		if user.Username != nil {
			claims.Username = *user.Username
		}
		if user.FirstName != nil {
			claims.FirstName = *user.FirstName
		}
		if user.LastName != nil {
			claims.LastName = *user.LastName
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = t.keyID

	tokenString, err := token.SignedString(t.privateKey)
	if err != nil {
		t.logger.Error().Err(err).Msg("Failed to sign access token")
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	cmd := &auth.StoreAccessTokenCommand{
		ID:        tokenID,
		TenantID:  user.TenantID,
		ClientID:  client.ID,
		UserID:    user.ID,
		SessionID: sessionID,
		TokenHash: t.hashToken(tokenString),
		Scopes:    scopes,
		ExpiresAt: now.Add(t.accessTokenTTL),
		CreatedAt: now,
	}

	if err := t.db.StoreAccessToken(ctx, cmd); err != nil {
		t.logger.Error().Err(err).Str("token_id", tokenID.String()).Msg("Failed to store access token")
		return "", fmt.Errorf("failed to store access token: %w", err)
	}

	t.logger.Info().
		Str("token_id", tokenID.String()).
		Str("user_id", user.ID.String()).
		Str("client_id", client.ClientID).
		Strs("scopes", scopes).
		Msg("Generated access token")

	return tokenString, nil
}

// GenerateRefreshToken implements ITokenService.
func (t *tokenService) GenerateRefreshToken(ctx context.Context, user *models.User, client *models.OAuth2Client, scopes []string, sessionID uuid.UUID, accessTokenID uuid.UUID) (string, error) {
	now := time.Now()
	tokenID := uuid.New()

	claims := &models.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID.String(),
			Subject:   user.ID.String(),
			Issuer:    t.issuer,
			Audience:  []string{client.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(t.refreshTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		TenantID:  user.TenantID.String(),
		SessionID: sessionID.String(),
		ClientID:  client.ClientID,
		Scopes:    scopes,
		TokenType: models.JWTRefreshTokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = t.keyID

	tokenString, err := token.SignedString(t.privateKey)
	if err != nil {
		t.logger.Error().Err(err).Msg("Failed to sign refresh token")
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	cmd := &auth.StoreRefreshTokenCommand{
		ID:            tokenID,
		TenantID:      user.TenantID,
		ClientID:      client.ID,
		UserID:        user.ID,
		SessionID:     sessionID,
		TokenHash:     t.hashToken(tokenString),
		AccessTokenID: accessTokenID,
		Scopes:        scopes,
		ExpiresAt:     now.Add(t.refreshTokenTTL),
		Used:          false,
		CreatedAt:     now,
	}

	if err := t.db.StoreRefreshToken(ctx, cmd); err != nil {
		t.logger.Error().Err(err).Str("token_id", tokenID.String()).Msg("Failed to store refresh token")
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	t.logger.Info().
		Str("token_id", tokenID.String()).
		Str("user_id", user.ID.String()).
		Str("client_id", client.ClientID).
		Str("access_token_id", accessTokenID.String()).
		Msg("Generated refresh token")

	return tokenString, nil
}

// GenerateIDToken implements ITokenService.
func (t *tokenService) GenerateIDToken(ctx context.Context, user *models.User, client *models.OAuth2Client, nonce string, sessionID uuid.UUID) (string, error) {
	now := time.Now()
	tokenID := uuid.New()

	claims := &models.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID.String(),
			Subject:   user.ID.String(),
			Issuer:    t.issuer,
			Audience:  []string{client.ClientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(t.idTokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		TenantID:      user.TenantID.String(),
		SessionID:     sessionID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		TokenType:     models.JWTIDTokenType,
	}

	if user.Username != nil {
		claims.Username = *user.Username
	}
	if user.FirstName != nil {
		claims.FirstName = *user.FirstName
	}
	if user.LastName != nil {
		claims.LastName = *user.LastName
	}

	if nonce != "" {
		claims.Metadata = map[string]any{
			"nonce": nonce,
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = t.keyID

	tokenString, err := token.SignedString(t.privateKey)
	if err != nil {
		t.logger.Error().Err(err).Msg("Failed to sign ID token")
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	t.logger.Info().
		Str("token_id", tokenID.String()).
		Str("user_id", user.ID.String()).
		Str("client_id", client.ClientID).
		Msg("Generated ID token")

	return tokenString, nil
}

// ValidateJWT implements ITokenService.
func (t *tokenService) ValidateJWT(ctx context.Context, tokenString string) (*models.JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &models.JWTClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return t.publicKey, nil
	})

	if err != nil {
		t.logger.Error().Err(err).Msg("Failed to parse JWT token")
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*models.JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// ValidateAccessToken implements ITokenService.
func (t *tokenService) ValidateAccessToken(ctx context.Context, token string) (*models.AccessToken, error) {
	claims, err := t.ValidateJWT(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}

	if claims.TokenType != models.JWTAccessTokenType {
		return nil, fmt.Errorf("invalid token type: expected %s, got %s", models.JWTAccessTokenType, claims.TokenType)
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	accessToken, err := t.getAccessTokenByID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	if accessToken.RevokedAt != nil {
		return nil, fmt.Errorf("token has been revoked")
	}

	if time.Now().After(accessToken.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	if accessToken.TokenHash != t.hashToken(token) {
		return nil, fmt.Errorf("token hash mismatch")
	}

	return accessToken, nil
}

// ValidateRefreshToken implements ITokenService.
func (t *tokenService) ValidateRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	claims, err := t.ValidateJWT(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT: %w", err)
	}

	if claims.TokenType != models.JWTRefreshTokenType {
		return nil, fmt.Errorf("invalid token type: expected %s, got %s", models.JWTRefreshTokenType, claims.TokenType)
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid token ID: %w", err)
	}

	refreshToken, err := t.getRefreshTokenByID(ctx, tokenID)
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if refreshToken.Used {
		return nil, fmt.Errorf("token has already been used")
	}

	if refreshToken.RevokedAt != nil {
		return nil, fmt.Errorf("token has been revoked")
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	if refreshToken.TokenHash != t.hashToken(token) {
		return nil, fmt.Errorf("token hash mismatch")
	}

	return refreshToken, nil
}

func (t *tokenService) RefreshTokens(ctx context.Context, refreshTokenString string) (*auth.TokenPair, error) {
	refreshToken, err := t.ValidateRefreshToken(ctx, refreshTokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	markUsedCmd := &auth.MarkRefreshTokenAsUsedCommand{
		ID:     refreshToken.ID,
		UsedAt: time.Now(),
	}

	if err := t.db.MarkRefreshTokenAsUsed(ctx, markUsedCmd); err != nil {
		return nil, fmt.Errorf("failed to mark refresh token as used: %w", err)
	}

	user, err := t.db.GetUserByID(ctx, refreshToken.TenantID, refreshToken.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	client, err := t.db.GetOAuth2ClientByTenant(ctx, refreshToken.TenantID, refreshToken.ClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	accessToken, err := t.GenerateAccessToken(ctx, user, client, refreshToken.Scopes, refreshToken.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	newRefreshToken, err := t.GenerateRefreshToken(ctx, user, client, refreshToken.Scopes, refreshToken.SessionID, uuid.New())
	if err != nil {
		return nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	return &auth.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    models.GeneratedTokenType,
		ExpiresIn:    int(t.accessTokenTTL.Seconds()),
	}, nil
}

func (s *tokenService) RevokeAllUserTokens(ctx context.Context, userID uuid.UUID, revokedBy uuid.UUID, reason string) error {
	cmd := &auth.RevokeAllUserTokensCommand{
		UserID:    userID,
		RevokedAt: time.Now(),
		RevokedBy: revokedBy,
		Reason:    reason,
	}

	if err := s.db.RevokeAllUserTokens(ctx, cmd); err != nil {
		return fmt.Errorf("failed to revoke all user tokens: %w", err)
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Str("revoked_by", revokedBy.String()).
		Str("reason", reason).
		Msg("Revoked all user tokens")

	return nil
}

// StoreAccessToken implements ITokenService.
func (t *tokenService) StoreAccessToken(ctx context.Context, token *models.AccessToken) error {
	panic("unimplemented")
}

// StoreRefreshToken implements ITokenService.
func (t *tokenService) StoreRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	panic("unimplemented")
}

// RevokeAccessToken implements ITokenService.
func (t *tokenService) RevokeAccessToken(ctx context.Context, tokenID uuid.UUID) error {
	panic("unimplemented")
}

// RevokeRefreshToken implements ITokenService.
func (t *tokenService) RevokeRefreshToken(ctx context.Context, tokenID uuid.UUID) error {
	panic("unimplemented")
}

// CleanupExpiredTokens implements ITokenService.
func (t *tokenService) CleanupExpiredTokens(ctx context.Context) error {
	panic("unimplemented")
}

func (t *tokenService) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func (t *tokenService) extractRoleNames(roles []*models.RoleReadModel) []string {
	var roleNames []string
	for _, role := range roles {
		roleNames = append(roleNames, role.Name)
	}
	return roleNames
}

func (t *tokenService) getUserRoles(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return []string{}, nil
}

func (t *tokenService) getUserPermissions(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return []string{}, nil
}

func (t *tokenService) getAccessTokenByID(ctx context.Context, tokenID uuid.UUID) (*models.AccessToken, error) {
	panic("unimplemented")
}

func (t *tokenService) getRefreshTokenByID(ctx context.Context, tokenID uuid.UUID) (*models.RefreshToken, error) {
	panic("unimplemented")
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
