package shared

type JWTTokenType string

const (
	JWTAccessTokenType  JWTTokenType = "access_token"
	JWTRefreshTokenType JWTTokenType = "refresh_token"
	JWTIDTokenType      JWTTokenType = "id_token"
)

type GeneratedTokenType string

const (
	GeneratedBearerTokenType GeneratedTokenType = "bearer"
)

var (
	StandardScopes = []string{
		"openid",
		"profile",
		"email",
		"offline_access",
	}

	StandardClaims = map[string][]string{
		"profile": {"sub", "name", "given_name", "family_name", "preferred_username", "picture", "updated_at"},
		"email":   {"email", "email_verified"},
		"openid":  {"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp"},
	}
)
