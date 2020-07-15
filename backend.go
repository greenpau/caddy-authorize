package jwt

import (
	"fmt"

	jwtlib "github.com/dgrijalva/jwt-go"
)

// Backend Errors
const (
	ErrInvalidSecretLength strError = "secrets less than 16 characters in length are not allowed"
)

// TokenBackend is the interface to provide key material.
type TokenBackend interface {
	ProvideKey(token *jwtlib.Token) (interface{}, error)
}

// SecretKeyTokenBackend hold symentric keys from HS family.
type SecretKeyTokenBackend struct {
	secret []byte
}

// NewSecretKeyTokenBackend returns SecretKeyTokenBackend instance.
func NewSecretKeyTokenBackend(s string) (*SecretKeyTokenBackend, error) {
	if len(s) < 16 {
		return nil, ErrInvalidSecretLength
	}
	b := &SecretKeyTokenBackend{
		secret: []byte(s),
	}
	return b, nil
}

// ProvideKey provides key material from SecretKeyTokenBackend.
func (b *SecretKeyTokenBackend) ProvideKey(token *jwtlib.Token) (interface{}, error) {
	if _, validMethod := token.Method.(*jwtlib.SigningMethodHMAC); !validMethod {
		return nil, fmt.Errorf(
			"signing method mismatch: HMAC (expected) vs. %v (received)",
			token.Header["alg"],
		)
	}
	return b.secret, nil
}
