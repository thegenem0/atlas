package oauth

type OAuth2AuthorizeRequest struct {
	ResponseType        string `json:"response_type" validate:"required"`
	ClientID            string `json:"client_id" validate:"required"`
	RedirectURI         string `json:"redirect_uri" validate:"required,url"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

type OAuth2TokenRequest struct {
	GrantType    string `json:"grant_type" validate:"required"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	CodeVerifier string `json:"code_verifier"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Scope        string `json:"scope"`
}
