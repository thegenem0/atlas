package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/thegenem0/atlas/internal/middleware"
	"github.com/thegenem0/atlas/internal/models"
	"github.com/thegenem0/atlas/internal/services"
)

type AuthHandler struct {
	authService *services.AuthService
}

func NewAuthHandler(authService *services.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get tenant from context
	tenant, ok := r.Context().Value(middleware.TenantContextKey).(*models.TenantReadModel)
	if !ok {
		http.Error(w, "Tenant not found in context", http.StatusInternalServerError)
		return
	}

	// Authenticate user
	result, err := h.authService.Login(r.Context(), tenant.ID, req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	result, err := h.authService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// In a full implementation, you'd invalidate the token/session
	// For now, just return success
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message": "Logged out successfully"}`))
}
