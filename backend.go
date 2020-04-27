package jwt

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
)

// TokenBackend is the interface to provide key material.
type TokenBackend interface {
	ProvideKey(token *jwt.Token) (interface{}, error)
}

// SecretKeyTokenBackend hold symentric keys from HS family.
type SecretKeyTokenBackend struct {
	secret []byte
}

// NewSecretKeyTokenBackend returns SecretKeyTokenBackend instance.
func NewSecretKeyTokenBackend(s string) (*SecretKeyTokenBackend, error) {
	if len(s) < 16 {
		return nil, fmt.Errorf("secrets less than 16 characters in length are not allowed")
	}
	b := &SecretKeyTokenBackend{
		secret: []byte(s),
	}
	return b, nil
}

// ProvideKey provides key material from SecretKeyTokenBackend.
func (b *SecretKeyTokenBackend) ProvideKey(token *jwt.Token) (interface{}, error) {
	if _, validMethod := token.Method.(*jwt.SigningMethodHMAC); !validMethod {
		return nil, fmt.Errorf(
			"signing method mismatch: HMAC (expected) vs. %v (received)",
			token.Header["alg"],
		)
	}
	return b.secret, nil
}
