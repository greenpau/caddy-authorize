package jwt

// CommonTokenConfig is common token-related configuration settings.
// The setting are used by TokenProvider and TokenValidator.
type CommonTokenConfig struct {
	TokenName   string `json:"token_name,omitempty" xml:"token_name" yaml:"token_name"`
	TokenSecret string `json:"token_secret,omitempty" xml:"token_secret" yaml:"token_secret"`
	TokenIssuer string `json:"token_issuer,omitempty" xml:"token_issuer" yaml:"token_issuer"`
	TokenOrigin string `json:"token_origin,omitempty" xml:"token_origin" yaml:"token_issuer"`
	// The expiration time of a token in seconds
	TokenLifetime      int    `json:"token_lifetime,omitempty" xml:"token_lifetime" yaml:"token_lifetime"`
	TokenSigningMethod string `json:"token_signing_method,omitempty" xml:"token_signing_method" yaml:"token_signing_method"`
}
