// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package user

import (
	"encoding/json"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"strings"
	"time"
)

// User is a user with claims and status.
type User struct {
	Claims          *Claims `json:"claims,omitempty" xml:"claims" yaml:"claims,omitempty"`
	Token           string  `json:"token,omitempty" xml:"token" yaml:"token,omitempty"`
	TokenName       string  `json:"token_name,omitempty" xml:"token_name" yaml:"token_name,omitempty"`
	TokenSource     string  `json:"token_source,omitempty" xml:"token_source" yaml:"token_source,omitempty"`
	requestHeaders  map[string]string
	requestIdentity map[string]interface{}
	Cached          bool `json:"cached,omitempty" xml:"cached" yaml:"cached,omitempty"`
	// Holds the map for all the claims parsed from a token.
	mkv map[string]interface{}
	// Holds the map for a subset of claims necessary for ACL evaluation.
	tkv map[string]interface{}
}

// Claims represents custom and standard JWT claims associated with User.
type Claims struct {
	Audience      []string               `json:"aud,omitempty" xml:"aud" yaml:"aud,omitempty"`
	ExpiresAt     int64                  `json:"exp,omitempty" xml:"exp" yaml:"exp,omitempty"`
	ID            string                 `json:"jti,omitempty" xml:"jti" yaml:"jti,omitempty"`
	IssuedAt      int64                  `json:"iat,omitempty" xml:"iat" yaml:"iat,omitempty"`
	Issuer        string                 `json:"iss,omitempty" xml:"iss" yaml:"iss,omitempty"`
	NotBefore     int64                  `json:"nbf,omitempty" xml:"nbf" yaml:"nbf,omitempty"`
	Subject       string                 `json:"sub,omitempty" xml:"sub" yaml:"sub,omitempty"`
	Name          string                 `json:"name,omitempty" xml:"name" yaml:"name,omitempty"`
	Email         string                 `json:"email,omitempty" xml:"email" yaml:"email,omitempty"`
	Roles         []string               `json:"roles,omitempty" xml:"roles" yaml:"roles,omitempty"`
	Origin        string                 `json:"origin,omitempty" xml:"origin" yaml:"origin,omitempty"`
	Scopes        []string               `json:"scopes,omitempty" xml:"scopes" yaml:"scopes,omitempty"`
	Organizations []string               `json:"org,omitempty" xml:"org" yaml:"org,omitempty"`
	AccessList    *AccessListClaim       `json:"acl,omitempty" xml:"acl" yaml:"acl,omitempty"`
	Address       string                 `json:"addr,omitempty" xml:"addr" yaml:"addr,omitempty"`
	PictureURL    string                 `json:"picture,omitempty" xml:"picture" yaml:"picture,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty" xml:"metadata" yaml:"metadata,omitempty"`
}

// AccessListClaim represents custom acl/paths claim
type AccessListClaim struct {
	Paths map[string]interface{} `json:"paths,omitempty" xml:"paths" yaml:"paths,omitempty"`
}

// Valid validates user claims.
func (c Claims) Valid() error {
	if c.ExpiresAt < time.Now().Unix() {
		return errors.ErrExpiredToken
	}
	return nil
}

// AsMap converts Claims struct to dictionary.
func (u *User) AsMap() map[string]interface{} {
	return u.mkv
}

// GetData return user claim felds and their values for the evaluation by an ACL.
func (u *User) GetData() map[string]interface{} {
	return u.tkv
}

// SetRequestHeaders sets request headers associated with the user.
func (u *User) SetRequestHeaders(m map[string]string) {
	u.requestHeaders = m
	return
}

// GetRequestHeaders returns request headers associated with the user.
func (u *User) GetRequestHeaders() map[string]string {
	return u.requestHeaders
}

// SetRequestIdentity sets request identity associated with the user.
func (u *User) SetRequestIdentity(m map[string]interface{}) {
	u.requestIdentity = m
	return
}

// GetRequestIdentity returns request identity associated with the user.
func (u *User) GetRequestIdentity() map[string]interface{} {
	return u.requestIdentity
}

// NewUser returns a user with associated claims.
func NewUser(data interface{}) (*User, error) {
	var m map[string]interface{}
	u := &User{}

	switch v := data.(type) {
	case string:
		m = make(map[string]interface{})
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return nil, err
		}
	case []uint8:
		m = make(map[string]interface{})
		if err := json.Unmarshal(v, &m); err != nil {
			return nil, err
		}
	case map[string]interface{}:
		m = v
	}

	if len(m) == 0 {
		return nil, errors.ErrInvalidUserDataType
	}

	c := &Claims{}
	mkv := make(map[string]interface{})
	tkv := make(map[string]interface{})

	if _, exists := m["aud"]; exists {
		switch m["aud"].(type) {
		case string:
			c.Audience = append(c.Audience, m["aud"].(string))
		case []interface{}:
			audiences := m["aud"].([]interface{})
			for _, audience := range audiences {
				switch audience.(type) {
				case string:
					c.Audience = append(c.Audience, audience.(string))
				default:
					return nil, errors.ErrInvalidAudience.WithArgs(audience)
				}
			}
		default:
			return nil, errors.ErrInvalidAudienceType.WithArgs(m["aud"])
		}
		switch len(c.Audience) {
		case 0:
		case 1:
			tkv["aud"] = c.Audience
			mkv["aud"] = c.Audience[0]
		default:
			tkv["aud"] = c.Audience
			mkv["aud"] = c.Audience
		}
	}

	if _, exists := m["exp"]; exists {
		switch exp := m["exp"].(type) {
		case float64:
			c.ExpiresAt = int64(exp)
		case int:
			c.ExpiresAt = int64(exp)
		case int64:
			c.ExpiresAt = exp
		case json.Number:
			v, _ := exp.Int64()
			c.ExpiresAt = v
		default:
			return nil, errors.ErrInvalidClaimExpiresAt.WithArgs(m["exp"])
		}
		mkv["exp"] = c.ExpiresAt
	}

	if _, exists := m["jti"]; exists {
		switch m["jti"].(type) {
		case string:
			c.ID = m["jti"].(string)
		default:
			return nil, errors.ErrInvalidIDClaimType.WithArgs(m["jti"])
		}
		tkv["jti"] = c.ID
		mkv["jti"] = c.ID
	}

	if _, exists := m["iat"]; exists {
		switch exp := m["iat"].(type) {
		case float64:
			c.IssuedAt = int64(exp)
		case int:
			c.IssuedAt = int64(exp)
		case int64:
			c.IssuedAt = exp
		case json.Number:
			v, _ := exp.Int64()
			c.IssuedAt = v
		default:
			return nil, errors.ErrInvalidClaimIssuedAt.WithArgs(m["iat"])
		}
		mkv["iat"] = c.IssuedAt
	}

	if _, exists := m["iss"]; exists {
		switch m["iss"].(type) {
		case string:
			c.Issuer = m["iss"].(string)
		default:
			return nil, errors.ErrInvalidIssuerClaimType.WithArgs(m["iss"])
		}
		tkv["iss"] = c.Issuer
		mkv["iss"] = c.Issuer
	}

	if _, exists := m["nbf"]; exists {
		switch exp := m["nbf"].(type) {
		case float64:
			c.NotBefore = int64(exp)
		case int:
			c.NotBefore = int64(exp)
		case int64:
			c.NotBefore = exp
		case json.Number:
			v, _ := exp.Int64()
			c.NotBefore = v
		default:
			return nil, errors.ErrInvalidClaimNotBefore.WithArgs(m["nbf"])
		}
		mkv["nbf"] = c.NotBefore
	}

	if _, exists := m["sub"]; exists {
		switch m["sub"].(type) {
		case string:
			c.Subject = m["sub"].(string)
		default:
			return nil, errors.ErrInvalidSubjectClaimType.WithArgs(m["sub"])
		}
		tkv["sub"] = c.Subject
		mkv["sub"] = c.Subject
	}

	for _, ma := range []string{"email", "mail"} {
		if _, exists := m[ma]; exists {
			switch m[ma].(type) {
			case string:
				c.Email = m[ma].(string)
			default:
				return nil, errors.ErrInvalidEmailClaimType.WithArgs(ma, m[ma])
			}
		}
	}
	if c.Email != "" {
		tkv["mail"] = c.Email
		mkv["mail"] = c.Email
	}

	if _, exists := m["name"]; exists {
		switch m["name"].(type) {
		case string:
			c.Name = m["name"].(string)
		case []interface{}:
			packedNames := []string{}
			names := m["name"].([]interface{})
			for _, n := range names {
				switch n.(type) {
				case string:
					parsedName := n.(string)
					if parsedName == c.Email {
						continue
					}
					packedNames = append(packedNames, parsedName)
				default:
					return nil, errors.ErrInvalidNameClaimType.WithArgs(m["name"])
				}
			}
			c.Name = strings.Join(packedNames, " ")
		default:
			return nil, errors.ErrInvalidNameClaimType.WithArgs(m["name"])
		}
		tkv["name"] = c.Name
		mkv["name"] = c.Name
	}

	for _, ra := range []string{"roles", "role", "groups", "group"} {
		if _, exists := m[ra]; exists {
			switch m[ra].(type) {
			case []interface{}:
				roles := m[ra].([]interface{})
				for _, role := range roles {
					switch role.(type) {
					case string:
						c.Roles = append(c.Roles, role.(string))
					default:
						return nil, errors.ErrInvalidRole.WithArgs(role)
					}
				}
			case string:
				roles := m[ra].(string)
				for _, role := range strings.Split(roles, " ") {
					c.Roles = append(c.Roles, role)
				}
			default:
				return nil, errors.ErrInvalidRoleType.WithArgs(m[ra])
			}
		}
	}

	if _, exists := m["app_metadata"]; exists {
		switch m["app_metadata"].(type) {
		case map[string]interface{}:
			appMetadata := m["app_metadata"].(map[string]interface{})
			if _, authzExists := appMetadata["authorization"]; authzExists {
				switch appMetadata["authorization"].(type) {
				case map[string]interface{}:
					appMetadataAuthz := appMetadata["authorization"].(map[string]interface{})
					if _, rolesExists := appMetadataAuthz["roles"]; rolesExists {
						switch appMetadataAuthz["roles"].(type) {
						case []interface{}:
							roles := appMetadataAuthz["roles"].([]interface{})
							for _, role := range roles {
								switch role.(type) {
								case string:
									c.Roles = append(c.Roles, role.(string))
								default:
									return nil, errors.ErrInvalidRole.WithArgs(role)
								}
							}
						default:
							return nil, errors.ErrInvalidAppMetadataRoleType.WithArgs(appMetadataAuthz["roles"])
						}
					}
				}
			}
		}
	}

	if _, exists := m["realm_access"]; exists {
		switch m["realm_access"].(type) {
		case map[string]interface{}:
			realmAccess := m["realm_access"].(map[string]interface{})
			if _, rolesExists := realmAccess["roles"]; rolesExists {
				switch realmAccess["roles"].(type) {
				case []interface{}:
					roles := realmAccess["roles"].([]interface{})
					for _, role := range roles {
						switch role.(type) {
						case string:
							c.Roles = append(c.Roles, role.(string))
						default:
							return nil, errors.ErrInvalidRole.WithArgs(role)
						}
					}
				}
			}
		}
	}

	for _, ra := range []string{"scopes", "scope"} {
		if _, exists := m[ra]; exists {
			switch m[ra].(type) {
			case []interface{}:
				scopes := m[ra].([]interface{})
				for _, scope := range scopes {
					switch scope.(type) {
					case string:
						c.Scopes = append(c.Scopes, scope.(string))
					default:
						return nil, errors.ErrInvalidScope.WithArgs(scope)
					}
				}
			case string:
				scopes := m[ra].(string)
				for _, scope := range strings.Split(scopes, " ") {
					c.Scopes = append(c.Scopes, scope)
				}
			default:
				return nil, errors.ErrInvalidScopeType.WithArgs(m[ra])
			}
		}
	}

	if len(c.Scopes) > 0 {
		tkv["scopes"] = c.Scopes
		mkv["scopes"] = strings.Join(c.Scopes, " ")
	}

	if _, exists := m["paths"]; exists {
		switch m["paths"].(type) {
		case []interface{}:
			paths := m["paths"].([]interface{})
			for _, path := range paths {
				switch path.(type) {
				case string:
					if c.AccessList == nil {
						c.AccessList = &AccessListClaim{}
					}
					if c.AccessList.Paths == nil {
						c.AccessList.Paths = make(map[string]interface{})
					}
					c.AccessList.Paths[path.(string)] = make(map[string]interface{})
				default:
					return nil, errors.ErrInvalidAccessListPath.WithArgs(path)
				}
			}
		}
	}

	if _, exists := m["acl"]; exists {
		switch m["acl"].(type) {
		case map[string]interface{}:
			acl := m["acl"].(map[string]interface{})
			if _, pathsExists := acl["paths"]; pathsExists {
				switch acl["paths"].(type) {
				case map[string]interface{}:
					paths := acl["paths"].(map[string]interface{})
					for path := range paths {
						if c.AccessList == nil {
							c.AccessList = &AccessListClaim{}
						}
						if c.AccessList.Paths == nil {
							c.AccessList.Paths = make(map[string]interface{})
						}
						c.AccessList.Paths[path] = make(map[string]interface{})
					}
				case []interface{}:
					paths := acl["paths"].([]interface{})
					for _, path := range paths {
						switch path.(type) {
						case string:
							if c.AccessList == nil {
								c.AccessList = &AccessListClaim{}
							}
							if c.AccessList.Paths == nil {
								c.AccessList.Paths = make(map[string]interface{})
							}
							c.AccessList.Paths[path.(string)] = make(map[string]interface{})
						default:
							return nil, errors.ErrInvalidAccessListPath.WithArgs(path)
						}
					}
				}
			}
		}
	}

	if c.AccessList != nil && c.AccessList.Paths != nil {
		tkv["acl"] = map[string]interface{}{
			"paths": c.AccessList.Paths,
		}
		mkv["acl"] = map[string]interface{}{
			"paths": c.AccessList.Paths,
		}
	}

	if _, exists := m["origin"]; exists {
		switch m["origin"].(type) {
		case string:
			c.Origin = m["origin"].(string)
		default:
			return nil, errors.ErrInvalidOriginClaimType.WithArgs(m["origin"])
		}
		tkv["origin"] = c.Origin
		mkv["origin"] = c.Origin
	}

	if _, exists := m["org"]; exists {
		switch m["org"].(type) {
		case []interface{}:
			orgs := m["org"].([]interface{})
			for _, org := range orgs {
				switch org.(type) {
				case string:
					c.Organizations = append(c.Organizations, org.(string))
				default:
					return nil, errors.ErrInvalidOrg.WithArgs(org)
				}
			}
		case string:
			orgs := m["org"].(string)
			for _, org := range strings.Split(orgs, " ") {
				c.Organizations = append(c.Organizations, org)
			}
		default:
			return nil, errors.ErrInvalidOrgType.WithArgs(m["org"])
		}
		tkv["org"] = c.Organizations
		mkv["org"] = strings.Join(c.Organizations, " ")
	}

	if _, exists := m["addr"]; exists {
		switch m["addr"].(type) {
		case string:
			c.Address = m["addr"].(string)
		default:
			return nil, errors.ErrInvalidAddrType.WithArgs(m["addr"])
		}
		tkv["addr"] = c.Address
		mkv["addr"] = c.Address
	}

	if _, exists := m["picture"]; exists {
		switch m["picture"].(type) {
		case string:
			c.PictureURL = m["picture"].(string)
		default:
			return nil, errors.ErrInvalidPictureClaimType.WithArgs(m["picture"])
		}
		mkv["picture"] = c.PictureURL
	}

	if _, exists := m["metadata"]; exists {
		switch m["metadata"].(type) {
		case map[string]interface{}:
			c.Metadata = m["metadata"].(map[string]interface{})
		default:
			return nil, errors.ErrInvalidMetadataClaimType.WithArgs(m["metadata"])
		}
		mkv["metadata"] = c.Metadata
	}

	if len(c.Roles) == 0 {
		c.Roles = append(c.Roles, "anonymous")
		c.Roles = append(c.Roles, "guest")
	}
	tkv["roles"] = c.Roles
	mkv["roles"] = c.Roles

	u.Claims = c
	u.mkv = mkv
	u.tkv = tkv
	return u, nil
}
