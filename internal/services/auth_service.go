// package services
//
// import (
// 	"context"
// 	"errors"
// 	"time"
//
// 	"github.com/google/uuid"
// 	"github.com/thegenem0/atlas/internal/database"
// 	"github.com/thegenem0/atlas/internal/models"
// 	"golang.org/x/crypto/bcrypt"
// 	"github.com/golang-jwt/jwt/v5"
// )
//
// type AuthService struct {
// 	db        database.IDatabase
// 	jwtSecret []byte
// }
//
// func NewAuthService(db database.IDatabase, jwtSecret []byte) *AuthService {
// 	return &AuthService{
// 		db:        db,
// 		jwtSecret: jwtSecret,
// 	}
// }
//
// type LoginResult struct {
// 	AccessToken  string                  `json:"access_token"`
// 	TokenType    string                  `json:"token_type"`
// 	ExpiresIn    int                     `json:"expires_in"`
// 	RefreshToken string                  `json:"refresh_token,omitempty"`
// 	User         *models.UserCredentials `json:"user"`
// }
//
// func (s *AuthService) Login(ctx context.Context, tenantID uuid.UUID, username, password string) (*LoginResult, error) {
// 	// Get user credentials with tenant validation
// 	creds, err := s.db.GetUserCredentials(ctx, tenantID, username)
// 	if err != nil {
// 		if errors.Is(err, database.ErrUserNotFound) {
// 			return nil, errors.New("invalid credentials")
// 		}
// 		return nil, err
// 	}
//
// 	// Check if user and tenant are enabled
// 	if !creds.Enabled {
// 		return nil, errors.New("user is disabled")
// 	}
//
// 	if !creds.TenantEnabled {
// 		return nil, errors.New("tenant is disabled")
// 	}
//
// 	// Verify password
// 	if err := bcrypt.CompareHashAndPassword([]byte(creds.PasswordHash), []byte(password)); err != nil {
// 		return nil, errors.New("invalid credentials")
// 	}
//
// 	// Generate access token
// 	accessToken, err := s.generateAccessToken(creds)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// Generate refresh token (optional)
// 	refreshToken, err := s.generateRefreshToken(creds)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &LoginResult{
// 		AccessToken:  accessToken,
// 		TokenType:    "Bearer",
// 		ExpiresIn:    3600, // 1 hour
// 		RefreshToken: refreshToken,
// 		User:         creds,
// 	}, nil
// }
//
// func (s *AuthService) generateAccessToken(user *models.UserCredentials) (string, error) {
// 	claims := jwt.MapClaims{
// 		"sub":       user.ID.String(),
// 		"username":  user.Username,
// 		"email":     user.Email,
// 		"tenant_id": user.TenantID.String(),
// 		"iat":       time.Now().Unix(),
// 		"exp":       time.Now().Add(time.Hour).Unix(),
// 		"aud":       "atlas-auth",
// 		"iss":       "atlas-auth-service",
// 		"typ":       "access_token",
// 	}
//
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	return token.SignedString(s.jwtSecret)
// }
//
// func (s *AuthService) generateRefreshToken(user *models.UserCredentials) (string, error) {
// 	claims := jwt.MapClaims{
// 		"sub":       user.ID.String(),
// 		"tenant_id": user.TenantID.String(),
// 		"iat":       time.Now().Unix(),
// 		"exp":       time.Now().Add(time.Hour * 24 * 30).Unix(), // 30 days
// 		"aud":       "atlas-auth",
// 		"iss":       "atlas-auth-service",
// 		"typ":       "refresh_token",
// 	}
//
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	return token.SignedString(s.jwtSecret)
// }
//
// func (s *AuthService) ValidateToken(tokenString string) (*jwt.Token, error) {
// 	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
// 			return nil, errors.New("invalid signing method")
// 		}
// 		return s.jwtSecret, nil
// 	})
// }
//
// func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*LoginResult, error) {
// 	// Validate refresh token
// 	token, err := s.ValidateToken(refreshToken)
// 	if err != nil {
// 		return nil, errors.New("invalid refresh token")
// 	}
//
// 	claims, ok := token.Claims.(jwt.MapClaims)
// 	if !ok || !token.Valid {
// 		return nil, errors.New("invalid refresh token")
// 	}
//
// 	// Check token type
// 	if claims["typ"] != "refresh_token" {
// 		return nil, errors.New("invalid token type")
// 	}
//
// 	// Get user ID and tenant ID
// 	userID, err := uuid.Parse(claims["sub"].(string))
// 	if err != nil {
// 		return nil, errors.New("invalid user ID in token")
// 	}
//
// 	tenantID, err := uuid.Parse(claims["tenant_id"].(string))
// 	if err != nil {
// 		return nil, errors.New("invalid tenant ID in token")
// 	}
//
// 	// Get fresh user credentials
// 	creds, err := s.db.GetUserByID(ctx, tenantID, userID)
// 	if err != nil {
// 		return nil, errors.New("user not found")
// 	}
//
// 	// Convert to UserCredentials format (you'd implement this)
// 	userCreds := &models.UserCredentials{
// 		ID:       creds.ID,
// 		TenantID: creds.TenantID,
// 		Username: creds.Username,
// 		Email:    creds.Email,
// 		Enabled:  creds.Enabled,
// 	}
//
// 	// Generate new tokens
// 	accessToken, err := s.generateAccessToken(userCreds)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	newRefreshToken, err := s.generateRefreshToken(userCreds)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &LoginResult{
// 		AccessToken:  accessToken,
// 		TokenType:    "Bearer",
// 		ExpiresIn:    3600,
// 		RefreshToken: newRefreshToken,
// 		User:         userCreds,
// 	}, nil
// }
