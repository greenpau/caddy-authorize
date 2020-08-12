package jwt

import (
	"crypto/rsa"

	jwtlib "github.com/dgrijalva/jwt-go"
)

// Backend Errors
const (
	ErrInvalidSecretLength strError = "secrets less than 16 characters in length are not allowed"
	ErrUnexpectedKID       strError = "the kid specified in the header was not found"
	ErrNoRSAKeyFound       strError = "no RSA key found"

	ErrUnexpectedSigningMethod strError = "signing method mismatch: %v (expected) vs. %v (received)"
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
		return nil, ErrUnexpectedSigningMethod.WithArgs("HS", token.Header["alg"])
	}
	return b.secret, nil
}

// RSAKeyTokenBackend hold asymentric keys from RS family.
type RSAKeyTokenBackend struct {
	secrets map[string]interface{}
}

// NewRSAKeyTokenBackend returns RSKeyTokenBackend instance.
func NewRSAKeyTokenBackend(k map[string]interface{}) *RSAKeyTokenBackend {
	b := &RSAKeyTokenBackend{
		secrets: k,
	}
	return b
}

// ProvideKey provides key material from RSKeyTokenBackend.
func (b *RSAKeyTokenBackend) ProvideKey(token *jwtlib.Token) (interface{}, error) {
	if _, validMethod := token.Method.(*jwtlib.SigningMethodRSA); !validMethod {
		return nil, ErrUnexpectedSigningMethod.WithArgs("RS", token.Header["alg"])
	}

	// check if we have a "kid" in the header we can use...
	if kid, ok := token.Header["kid"].(string); ok {
		if val, ok := b.secrets[kid]; ok {
			switch key := val.(type) {
			case *rsa.PrivateKey:
				return &key.PublicKey, nil
			case *rsa.PublicKey:
				return key, nil
			}
			// it should never get here
			// becuase only RSA keys should
			// be put into the b.secrets field
		}
		return nil, ErrUnexpectedKID
	}

	// no kid, then we should have a "0", as that's the default value
	if val, ok := b.secrets[defaultKeyID]; ok {
		switch key := val.(type) {
		case *rsa.PrivateKey:
			return &key.PublicKey, nil
		case *rsa.PublicKey:
			return key, nil
		}
	}

	return nil, ErrNoRSAKeyFound
}
