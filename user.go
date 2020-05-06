package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	jwtlib "github.com/dgrijalva/jwt-go"
	"time"
)

var methods = map[string]bool{
	"HS256": true,
	"HS384": true,
	"HS512": true,
	//"RS256": true,
	//"RS384": true,
	//"RS512": true,
	//"ES256": true,
	//"ES384": true,
	//"ES512": true,
}

// UserClaims represents custom and standard JWT claims.
type UserClaims struct {
	Audience      string   `json:"aud,omitempty" xml:"aud" yaml:"aud,omitempty"`
	ExpiresAt     int64    `json:"exp,omitempty" xml:"exp" yaml:"exp,omitempty"`
	ID            string   `json:"jti,omitempty" xml:"jti" yaml:"jti,omitempty"`
	IssuedAt      int64    `json:"iat,omitempty" xml:"iat" yaml:"iat,omitempty"`
	Issuer        string   `json:"iss,omitempty" xml:"iss" yaml:"iss,omitempty"`
	NotBefore     int64    `json:"nbf,omitempty" xml:"nbf" yaml:"nbf,omitempty"`
	Subject       string   `json:"sub,omitempty" xml:"sub" yaml:"sub,omitempty"`
	Name          string   `json:"name,omitempty" xml:"name" yaml:"name,omitempty"`
	Email         string   `json:"email,omitempty" xml:"email" yaml:"email,omitempty"`
	Roles         []string `json:"roles,omitempty" xml:"roles" yaml:"roles,omitempty"`
	Origin        string   `json:"origin,omitempty" xml:"origin" yaml:"origin,omitempty"`
	Scope         string   `json:"scope,omitempty" xml:"scope" yaml:"scope,omitempty"`
	Organizations []string `json:"org,omitempty" xml:"org" yaml:"org,omitempty"`
}

// Valid validates user claims.
func (u UserClaims) Valid() error {
	if u.ExpiresAt < time.Now().Unix() {
		return errors.New("token expired")
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
		m["mail"] = u.Email
	}
	if len(u.Roles) > 0 {
		m["roles"] = u.Roles
	}
	if u.Origin != "" {
		m["origin"] = u.Origin
	}
	if u.Scope != "" {
		m["scope"] = u.Scope
	}
	if len(u.Organizations) > 0 {
		m["org"] = u.Organizations
	}
	return m
}

// NewUserClaimsFromMap returns UserClaims.
func NewUserClaimsFromMap(m map[string]interface{}) (*UserClaims, error) {
	u := &UserClaims{}

	if _, exists := m["aud"]; exists {
		u.Audience = m["aud"].(string)
	}
	if _, exists := m["exp"]; exists {
		switch exp := m["exp"].(type) {
		case float64:
			u.ExpiresAt = int64(exp)
		case json.Number:
			v, _ := exp.Int64()
			u.ExpiresAt = v
		default:
			return nil, fmt.Errorf("invalid exp type")
		}
	}

	if _, exists := m["jti"]; exists {
		u.ID = m["jti"].(string)
	}

	if _, exists := m["iat"]; exists {
		switch exp := m["iat"].(type) {
		case float64:
			u.IssuedAt = int64(exp)
		case json.Number:
			v, _ := exp.Int64()
			u.IssuedAt = v
		default:
			return nil, fmt.Errorf("invalid iat type")
		}
	}

	if _, exists := m["iss"]; exists {
		u.Issuer = m["iss"].(string)
	}

	if _, exists := m["nbf"]; exists {
		switch exp := m["nbf"].(type) {
		case float64:
			u.NotBefore = int64(exp)
		case json.Number:
			v, _ := exp.Int64()
			u.NotBefore = v
		default:
			return nil, fmt.Errorf("invalid nbf type")
		}
	}

	if _, exists := m["sub"]; exists {
		u.Subject = m["sub"].(string)
	}

	if _, exists := m["name"]; exists {
		u.Name = m["name"].(string)
	}

	if _, exists := m["mail"]; exists {
		u.Email = m["mail"].(string)
	}

	if _, exists := m["roles"]; exists {
		switch m["roles"].(type) {
		case []interface{}:
			roles := m["roles"].([]interface{})
			for _, role := range roles {
				switch role.(type) {
				case string:
					u.Roles = append(u.Roles, role.(string))
				default:
					return nil, fmt.Errorf("invalid role type %T in roles", role)
				}
			}
		default:
			return nil, fmt.Errorf("invalid roles type %T", m["roles"])
		}
	}

	if _, exists := m["origin"]; exists {
		u.Origin = m["origin"].(string)
	}

	if _, exists := m["scope"]; exists {
		u.Scope = m["scope"].(string)
	}

	if _, exists := m["org"]; exists {
		switch m["org"].(type) {
		case []interface{}:
			orgs := m["org"].([]interface{})
			for _, org := range orgs {
				switch org.(type) {
				case string:
					u.Organizations = append(u.Organizations, org.(string))
				default:
					return nil, fmt.Errorf("invalid org type %T in orgs", org)
				}
			}
		default:
			return nil, fmt.Errorf("invalid orgs type %T", m["org"])
		}
	}

	return u, nil
}

// GetToken returns a signed JWT token
func (u *UserClaims) GetToken(method string, secret []byte) (string, error) {
	return GetToken(method, secret, *u)
}

// GetToken returns a signed JWT token
func GetToken(method string, secret []byte, claims UserClaims) (string, error) {
	if _, exists := methods[method]; !exists {
		return "", fmt.Errorf("unsupported signing method")
	}

	if secret == nil {
		return "", fmt.Errorf("empty secrets are not supported")
	}

	sm := jwtlib.GetSigningMethod(method)
	token := jwtlib.NewWithClaims(sm, claims)
	signedToken, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
