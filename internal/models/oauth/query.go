package oauth

import "time"

type OAuth2ClientReadModel struct {
	ID                      string    `db:"id"`
	TenantID                string    `db:"tenant_id"`
	ClientID                string    `db:"client_id"`
	ClientSecret            string    `db:"client_secret"`
	RedirectURIs            []string  `db:"redirect_uris"`
	GrantTypes              []string  `db:"grant_types"`
	ResponseTypes           []string  `db:"response_types"`
	Scopes                  []string  `db:"scopes"`
	TokenEndpointAuthMethod string    `db:"token_endpoint_auth_method"`
	CreatedAt               time.Time `db:"created_at"`
	UpdatedAt               time.Time `db:"updated_at"`
}

type ClientFilter struct {
	Limit  int
	Offset int
}
