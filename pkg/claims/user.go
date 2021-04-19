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

package claims

import (
	"encoding/json"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"strings"
	"time"
)

// UserClaims represents custom and standard JWT claims.
type UserClaims struct {
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
func (u UserClaims) Valid() error {
	if u.ExpiresAt < time.Now().Unix() {
		return errors.ErrExpiredToken
	}
	return nil
}

// AsMap converts UserClaims struct to dictionary.
func (u UserClaims) AsMap() map[string]interface{} {
	m := map[string]interface{}{}
	if len(u.Audience) == 1 {
		m["aud"] = u.Audience[0]
	} else if len(u.Audience) > 1 {
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
	if len(u.Scopes) > 0 {
		m["scopes"] = strings.Join(u.Scopes, " ")
	}
	if len(u.Organizations) > 0 {
		m["org"] = strings.Join(u.Organizations, " ")
	}
	if u.Address != "" {
		m["addr"] = u.Address
	}
	if u.AccessList != nil {
		if u.AccessList.Paths != nil {
			if _, exists := m["acl"]; !exists {
				m["acl"] = map[string]interface{}{
					"paths": u.AccessList.Paths,
				}
			} else {
				existingACL := m["acl"].(map[string]interface{})
				existingACL["paths"] = u.AccessList.Paths
				m["acl"] = existingACL
			}
		}
	}
	if u.PictureURL != "" {
		m["picture"] = u.PictureURL
	}
	if u.Metadata != nil {
		m["metadata"] = u.Metadata
	}
	return m
}

// NewUserClaimsFromJSON returns UserClaims.
func NewUserClaimsFromJSON(s string) (*UserClaims, error) {
	m := make(map[string]interface{})
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, err
	}
	return NewUserClaimsFromMap(m)
}

// NewUserClaimsFromMap returns UserClaims.
func NewUserClaimsFromMap(m map[string]interface{}) (*UserClaims, error) {
	u := &UserClaims{}

	if _, exists := m["aud"]; exists {
		switch m["aud"].(type) {
		case string:
			u.Audience = append(u.Audience, m["aud"].(string))
		case []interface{}:
			audiences := m["aud"].([]interface{})
			for _, audience := range audiences {
				switch audience.(type) {
				case string:
					u.Audience = append(u.Audience, audience.(string))
				default:
					return nil, errors.ErrInvalidAudience.WithArgs(audience)
				}
			}
		default:
			return nil, errors.ErrInvalidAudienceType.WithArgs(m["aud"])
		}
	}

	if _, exists := m["exp"]; exists {
		switch exp := m["exp"].(type) {
		case float64:
			u.ExpiresAt = int64(exp)
		case json.Number:
			v, _ := exp.Int64()
			u.ExpiresAt = v
		default:
			return nil, errors.ErrInvalidClaimExpiresAt
		}
	}

	if _, exists := m["jti"]; exists {
		switch m["jti"].(type) {
		case string:
			u.ID = m["jti"].(string)
		default:
			return nil, errors.ErrInvalidIDClaimType.WithArgs(m["jti"])
		}
	}

	if _, exists := m["iat"]; exists {
		switch exp := m["iat"].(type) {
		case float64:
			u.IssuedAt = int64(exp)
		case json.Number:
			v, _ := exp.Int64()
			u.IssuedAt = v
		default:
			return nil, errors.ErrInvalidClaimIssuedAt
		}
	}

	if _, exists := m["iss"]; exists {
		switch m["iss"].(type) {
		case string:
			u.Issuer = m["iss"].(string)
		default:
			return nil, errors.ErrInvalidIssuerClaimType.WithArgs(m["iss"])
		}
	}

	if _, exists := m["nbf"]; exists {
		switch exp := m["nbf"].(type) {
		case float64:
			u.NotBefore = int64(exp)
		case json.Number:
			v, _ := exp.Int64()
			u.NotBefore = v
		default:
			return nil, errors.ErrInvalidClaimNotBefore
		}
	}

	if _, exists := m["sub"]; exists {
		switch m["sub"].(type) {
		case string:
			u.Subject = m["sub"].(string)
		default:
			return nil, errors.ErrInvalidSubjectClaimType.WithArgs(m["sub"])
		}
	}

	for _, ma := range []string{"email", "mail"} {
		if _, exists := m[ma]; exists {
			switch m[ma].(type) {
			case string:
				u.Email = m[ma].(string)
			default:
				return nil, errors.ErrInvalidEmailClaimType.WithArgs(ma, m[ma])
			}
		}
	}

	if _, exists := m["name"]; exists {
		switch m["name"].(type) {
		case string:
			u.Name = m["name"].(string)
		case []interface{}:
			packedNames := []string{}
			names := m["name"].([]interface{})
			for _, n := range names {
				switch n.(type) {
				case string:
					parsedName := n.(string)
					if parsedName == u.Email {
						continue
					}
					packedNames = append(packedNames, parsedName)
				default:
					return nil, errors.ErrInvalidNameClaimType.WithArgs(m["name"])
				}
			}
			u.Name = strings.Join(packedNames, " ")
		default:
			return nil, errors.ErrInvalidNameClaimType.WithArgs(m["name"])
		}
	}

	for _, ra := range []string{"roles", "role", "groups", "group"} {
		if _, exists := m[ra]; exists {
			switch m[ra].(type) {
			case []interface{}:
				roles := m[ra].([]interface{})
				for _, role := range roles {
					switch role.(type) {
					case string:
						u.Roles = append(u.Roles, role.(string))
					default:
						return nil, errors.ErrInvalidRole.WithArgs(role)
					}
				}
			case string:
				roles := m[ra].(string)
				for _, role := range strings.Split(roles, " ") {
					u.Roles = append(u.Roles, role)
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
									u.Roles = append(u.Roles, role.(string))
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
							u.Roles = append(u.Roles, role.(string))
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
						u.Scopes = append(u.Scopes, scope.(string))
					default:
						return nil, errors.ErrInvalidScope.WithArgs(scope)
					}
				}
			case string:
				scopes := m[ra].(string)
				for _, scope := range strings.Split(scopes, " ") {
					u.Scopes = append(u.Scopes, scope)
				}
			default:
				return nil, errors.ErrInvalidScopeType.WithArgs(m[ra])
			}
		}
	}

	if _, exists := m["paths"]; exists {
		switch m["paths"].(type) {
		case []interface{}:
			paths := m["paths"].([]interface{})
			for _, path := range paths {
				switch path.(type) {
				case string:
					if u.AccessList == nil {
						u.AccessList = &AccessListClaim{}
					}
					if u.AccessList.Paths == nil {
						u.AccessList.Paths = make(map[string]interface{})
					}
					u.AccessList.Paths[path.(string)] = make(map[string]interface{})
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
						if u.AccessList == nil {
							u.AccessList = &AccessListClaim{}
						}
						if u.AccessList.Paths == nil {
							u.AccessList.Paths = make(map[string]interface{})
						}
						u.AccessList.Paths[path] = make(map[string]interface{})
					}
				case []interface{}:
					paths := acl["paths"].([]interface{})
					for _, path := range paths {
						switch path.(type) {
						case string:
							if u.AccessList == nil {
								u.AccessList = &AccessListClaim{}
							}
							if u.AccessList.Paths == nil {
								u.AccessList.Paths = make(map[string]interface{})
							}
							u.AccessList.Paths[path.(string)] = make(map[string]interface{})
						default:
							return nil, errors.ErrInvalidAccessListPath.WithArgs(path)
						}
					}
				}
			}
		}
	}

	if _, exists := m["origin"]; exists {
		switch m["origin"].(type) {
		case string:
			u.Origin = m["origin"].(string)
		default:
			return nil, errors.ErrInvalidOriginClaimType.WithArgs(m["origin"])
		}
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
					return nil, errors.ErrInvalidOrg.WithArgs(org)
				}
			}
		case string:
			orgs := m["org"].(string)
			for _, org := range strings.Split(orgs, " ") {
				u.Organizations = append(u.Organizations, org)
			}
		default:
			return nil, errors.ErrInvalidOrgType.WithArgs(m["org"])
		}
	}

	if _, exists := m["addr"]; exists {
		switch m["addr"].(type) {
		case string:
			u.Address = m["addr"].(string)
		default:
			return nil, errors.ErrInvalidAddrType.WithArgs(m["addr"])
		}
	}

	if _, exists := m["picture"]; exists {
		switch m["picture"].(type) {
		case string:
			u.PictureURL = m["picture"].(string)
		default:
			return nil, errors.ErrInvalidPictureClaimType.WithArgs(m["picture"])
		}
	}

	if _, exists := m["metadata"]; exists {
		switch m["metadata"].(type) {
		case map[string]interface{}:
			u.Metadata = m["metadata"].(map[string]interface{})
		default:
			return nil, errors.ErrInvalidMetadataClaimType.WithArgs(m["metadata"])
		}
	}

	if len(u.Roles) == 0 {
		u.Roles = append(u.Roles, "anonymous")
		u.Roles = append(u.Roles, "guest")
	}

	return u, nil
}

// ExtractKV extracts fields and their value for the evaluation by an ACL.
func (u UserClaims) ExtractKV() map[string]interface{} {
	m := map[string]interface{}{}
	if len(u.Audience) > 0 {
		m["aud"] = u.Audience
	}
	if u.ExpiresAt > 0 {
		m["exp"] = u.ExpiresAt
	}
	if u.ID != "" {
		m["jti"] = u.ID
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
	if len(u.Scopes) > 0 {
		m["scopes"] = u.Scopes
	}
	if len(u.Organizations) > 0 {
		m["org"] = u.Organizations
	}
	if u.Address != "" {
		m["addr"] = u.Address
	}
	if u.AccessList != nil {
		if u.AccessList.Paths != nil {
			m["acl"] = u.AccessList.Paths
		}
	}
	return m
}
