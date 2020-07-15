package jwt

import (
	"fmt"
)

// Grantor Errors
const (
	ErrEmptySecret strError = "grantor token secret not configured"
	ErrNoClaims    strError = "provided claims are nil"
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
		return ErrEmptySecret
	}
	return nil
}

// GrantToken returns a signed token from user claims
func (g *TokenGrantor) GrantToken(method string, claims *UserClaims) (string, error) {
	if _, exists := methods[method]; !exists {
		return "", fmt.Errorf("grantor does not support %s token signing method", method)
	}
	if claims == nil {
		return "", ErrNoClaims
	}
	if g.TokenSecret == "" {
		return "", ErrEmptySecret
	}
	return claims.GetToken(method, []byte(g.TokenSecret))
}
