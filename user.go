package jwt

import (
	"errors"
	"fmt"
	jwtlib "github.com/dgrijalva/jwt-go"
	"time"
)

var methods = map[string]bool{
	"HS256": true,
	"HS384": true,
	"HS512": true,
	"RS256": true,
	"RS384": true,
	"RS512": true,
	"ES256": true,
	"ES384": true,
	"ES512": true,
}

// UserClaims represents custom and standard JWT claims.
type UserClaims struct {
	Audience  string   `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	ID        string   `json:"jti,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	Subject   string   `json:"sub,omitempty"`
	Name      string   `json:"name,omitempty"`
	Email     string   `json:"email,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	Origin    string   `json:"origin,omitempty"`
}

// Valid validates user claims.
func (u UserClaims) Valid() error {
	if u.ExpiresAt < time.Now().Unix() {
		return errors.New("The access token expired")
	}
	return nil
}

// AsMap converts UserClaims struct to dictionary.
func (u UserClaims) AsMap() map[string]interface{} {
	m := map[string]interface{}{}
	if u.Audience != "" {
		m["aud"] = u.Audience
	}
	if u.ExpiresAt > 0 {
		m["exp"] = u.ExpiresAt
	}
	if u.ID != "" {
		m["jti"] = u.ID
	}
	if u.IssuedAt > 0 {
		m["iat"] = u.IssuedAt
	}
	if u.Issuer != "" {
		m["iss"] = u.Issuer
	}
	if u.NotBefore > 0 {
		m["nbf"] = u.NotBefore
	}
	if u.Subject != "" {
		m["sub"] = u.Subject
	}
	if u.Name != "" {
		m["name"] = u.Name
	}
	if u.Email != "" {
		m["mail"] = u.Name
	}
	if len(u.Roles) > 0 {
		m["roles"] = u.Roles
	}
	if u.Origin != "" {
		m["origin"] = u.Origin
	}
	return m
}

// GetToken returns a signed JWT token
func (u *UserClaims) GetToken(method string, secret []byte) (string, error) {
	return GetToken(method, secret, *u)
}

// GetToken returns a signed JWT token
func GetToken(method string, secret []byte, claims UserClaims) (string, error) {
	if _, exists := methods[method]; !exists {
		return "", fmt.Errorf("Unsupported signing method")
	}

	if secret == nil {
		return "", fmt.Errorf("Empty secrets are not supported")
	}

	sm := jwtlib.GetSigningMethod(method)
	token := jwtlib.NewWithClaims(sm, claims)
	signedToken, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
