package jwt

import (
	"fmt"
)

// TokenGrantor creates and issues JWT tokens.
type TokenGrantor struct {
	CommonTokenConfig
}

// NewTokenGrantor returns an instance of TokenGrantor
func NewTokenGrantor() *TokenGrantor {
	g := &TokenGrantor{}
	return g
}

// Validate check whether TokenGrantor has valid configuration.
func (g *TokenGrantor) Validate() error {
	if g.TokenSecret == "" {
		return fmt.Errorf("grantor token secret not configured")
	}
	return nil
}

// GrantToken returns a signed token from user claims
func (g *TokenGrantor) GrantToken(method string, claims *UserClaims) (string, error) {
	if _, exists := methods[method]; !exists {
		return "", fmt.Errorf("grantor does not support %s token signing method", method)
	}
	if claims == nil {
		return "", fmt.Errorf("provided claims are nil")
	}
	if g.TokenSecret == "" {
		return "", fmt.Errorf("grantor token secret not configured")
	}
	return claims.GetToken(method, []byte(g.TokenSecret))
}
