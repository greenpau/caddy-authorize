// Copyright 2020 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package user

import (
	"encoding/json"
	"fmt"
	"github.com/greenpau/caddy-authorize/pkg/errors"
	cfgutils "github.com/greenpau/caddy-authorize/pkg/utils/cfg"
	"strings"
	"time"
)

/*
var reservedFields = map[string]interface{}{
	"email":        true,
	"role":         true,
	"groups":       true,
	"group":        true,
	"app_metadata": true,
	"realm_access": true,
	"paths":        true,
	"acl":          true,
}
*/

// User is a user with claims and status.
type User struct {
	Claims          *Claims       `json:"claims,omitempty" xml:"claims,omitempty" yaml:"claims,omitempty"`
	Token           string        `json:"token,omitempty" xml:"token,omitempty" yaml:"token,omitempty"`
	TokenName       string        `json:"token_name,omitempty" xml:"token_name,omitempty" yaml:"token_name,omitempty"`
	TokenSource     string        `json:"token_source,omitempty" xml:"token_source,omitempty" yaml:"token_source,omitempty"`
	Authenticator   Authenticator `json:"authenticator,omitempty" xml:"authenticator,omitempty" yaml:"authenticator,omitempty"`
	Checkpoints     []*Checkpoint `json:"checkpoints,omitempty" xml:"checkpoints,omitempty" yaml:"checkpoints,omitempty"`
	Authorized      bool          `json:"authorized,omitempty" xml:"authorized,omitempty" yaml:"authorized,omitempty"`
	FrontendLinks   []string      `json:"frontend_links,omitempty" xml:"frontend_links,omitempty" yaml:"frontend_links,omitempty"`
	Locked          bool          `json:"locked,omitempty" xml:"locked,omitempty" yaml:"locked,omitempty"`
	Cached          bool          `json:"cached,omitempty" xml:"cached,omitempty" yaml:"cached,omitempty"`
	requestHeaders  map[string]string
	requestIdentity map[string]interface{}
	// Holds the map for all the claims parsed from a token.
	mkv map[string]interface{}
	// Holds the map for a subset of claims necessary for ACL evaluation.
	tkv map[string]interface{}
	// Holds the map of the user roles.
	rkv map[string]interface{}
}

// Checkpoint represents additional checks that a user needs to pass. Once
// a user passes the checks, the Authorized is set to true. The checks
// could be the acceptance of the terms of use, multi-factor authentication,
// etc.
type Checkpoint struct {
	ID             int    `json:"id,omitempty" xml:"id,omitempty" yaml:"id,omitempty"`
	Name           string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Type           string `json:"type,omitempty" xml:"type,omitempty" yaml:"type,omitempty"`
	Parameters     string `json:"parameters,omitempty" xml:"parameters,omitempty" yaml:"parameters,omitempty"`
	Passed         bool   `json:"passed,omitempty" xml:"passed,omitempty" yaml:"passed,omitempty"`
	FailedAttempts int    `json:"failed_attempts,omitempty" xml:"failed_attempts,omitempty" yaml:"failed_attempts,omitempty"`
}

// Authenticator represents authentication backend
type Authenticator struct {
	Name          string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Realm         string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Method        string `json:"method,omitempty" xml:"method,omitempty" yaml:"method,omitempty"`
	TempSecret    string `json:"temp_secret,omitempty" xml:"temp_secret,omitempty" yaml:"temp_secret,omitempty"`
	TempSessionID string `json:"temp_session_id,omitempty" xml:"temp_session_id,omitempty" yaml:"temp_session_id,omitempty"`
	TempChallenge string `json:"temp_challenge,omitempty" xml:"temp_challenge,omitempty" yaml:"temp_challenge,omitempty"`
	URL           string `json:"url,omitempty" xml:"url,omitempty" yaml:"url,omitempty"`
	LoginHint     string `json:"login_hint,omitempty" xml:"login_hint,omitempty" yaml:"login_hint,omitempty"`
}

// Claims represents custom and standard JWT claims associated with User.
type Claims struct {
	Audience      []string               `json:"aud,omitempty" xml:"aud,omitempty" yaml:"aud,omitempty"`
	ExpiresAt     int64                  `json:"exp,omitempty" xml:"exp,omitempty" yaml:"exp,omitempty"`
	ID            string                 `json:"jti,omitempty" xml:"jti,omitempty" yaml:"jti,omitempty"`
	IssuedAt      int64                  `json:"iat,omitempty" xml:"iat,omitempty" yaml:"iat,omitempty"`
	Issuer        string                 `json:"iss,omitempty" xml:"iss,omitempty" yaml:"iss,omitempty"`
	NotBefore     int64                  `json:"nbf,omitempty" xml:"nbf,omitempty" yaml:"nbf,omitempty"`
	Subject       string                 `json:"sub,omitempty" xml:"sub,omitempty" yaml:"sub,omitempty"`
	Name          string                 `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Email         string                 `json:"email,omitempty" xml:"email,omitempty" yaml:"email,omitempty"`
	Roles         []string               `json:"roles,omitempty" xml:"roles,omitempty" yaml:"roles,omitempty"`
	Origin        string                 `json:"origin,omitempty" xml:"origin,omitempty" yaml:"origin,omitempty"`
	Scopes        []string               `json:"scopes,omitempty" xml:"scopes,omitempty" yaml:"scopes,omitempty"`
	Organizations []string               `json:"org,omitempty" xml:"org,omitempty" yaml:"org,omitempty"`
	AccessList    *AccessListClaim       `json:"acl,omitempty" xml:"acl,omitempty" yaml:"acl,omitempty"`
	Address       string                 `json:"addr,omitempty" xml:"addr,omitempty" yaml:"addr,omitempty"`
	PictureURL    string                 `json:"picture,omitempty" xml:"picture,omitempty" yaml:"picture,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty" xml:"metadata,omitempty" yaml:"metadata,omitempty"`
	custom        map[string]interface{}
}

// AccessListClaim represents custom acl/paths claim
type AccessListClaim struct {
	Paths map[string]interface{} `json:"paths,omitempty" xml:"paths,omitempty" yaml:"paths,omitempty"`
}

// Valid validates user claims.
func (c Claims) Valid() error {
	if c.ExpiresAt < time.Now().Unix() {
		return errors.ErrExpiredToken
	}
	return nil
}

/*
func (c *Claims) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	if len(c.Audience) > 0 {
		m["aud"] = c.Audience
	}
	if c.ExpiresAt > 0 {
		m["exp"] = c.ExpiresAt
	}
	if c.IssuedAt > 0 {
		m["iat"] = c.IssuedAt
	}
	if c.NotBefore > 0 {
		m["nbf"] = c.NotBefore
	}
	if c.ID != "" {
		m["jti"] = c.ID
	}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	if c.Name != "" {
		m["sub"] = c.Name
	}
	if c.Email != "" {
		m["email"] = c.Email
	}
	if len(c.Roles) > 0 {
		m["roles"] = c.Roles
	}
	if c.Origin != "" {
		m["origin"] = c.Origin
	}
	if len(c.Scopes) > 0 {
		m["scopes"] = c.Scopes
	}
	if len(c.Organizations) > 0 {
		m["org"] = c.Organizations
	}
	if c.AccessList != nil {
		m["acl"] = c.AccessList
	}
	if c.Address != "" {
		m["addr"] = c.Address
	}
	if c.PictureURL != "" {
		m["picture"] = c.PictureURL
	}
	if c.Metadata != nil {
		m["metadata"] = c.Metadata
	}
	if c.custom != nil {
		for k, v := range c.custom {
			m[k] = v
		}
	}
	j, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return j, nil
}
*/

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

// SetExpiresAtClaim sets ExpiresAt claim.
func (u *User) SetExpiresAtClaim(i int64) {
	u.Claims.ExpiresAt = i
	u.mkv["exp"] = i
}

// SetIssuedAtClaim sets IssuedAt claim.
func (u *User) SetIssuedAtClaim(i int64) {
	u.Claims.IssuedAt = i
	u.mkv["iat"] = i
}

// SetNotBeforeClaim sets NotBefore claim.
func (u *User) SetNotBeforeClaim(i int64) {
	u.Claims.NotBefore = i
	u.mkv["nbf"] = i
}

// SetRolesClaim sets Roles claim
func (u *User) SetRolesClaim(roles []string) {
	u.Claims.Roles = roles
	u.tkv["roles"] = roles
	u.mkv["roles"] = roles
	for k := range u.rkv {
		delete(u.rkv, k)
	}
	for _, roleName := range roles {
		u.rkv[roleName] = true
	}
}

// HasRole checks whether a user has any of the provided roles.
func (u *User) HasRole(roles ...string) bool {
	for _, role := range roles {
		if _, exists := u.rkv[role]; exists {
			return true
		}
	}
	return false
}

// HasRoles checks whether a user has all of the provided roles.
func (u *User) HasRoles(roles ...string) bool {
	for _, role := range roles {
		if _, exists := u.rkv[role]; !exists {
			return false
		}
	}
	return true
}

// AddFrontendLinks adds frontend links to User instance.
func (u *User) AddFrontendLinks(v interface{}) error {
	var entries []string
	switch data := v.(type) {
	case string:
		entries = append(entries, data)
	case []string:
		entries = data
	case []interface{}:
		for _, entry := range data {
			switch entry.(type) {
			case string:
				entries = append(entries, entry.(string))
			default:
				return errors.ErrCheckpointInvalidType.WithArgs(data, data)
			}
		}
	default:
		return errors.ErrFrontendLinkInvalidType.WithArgs(data, data)
	}
	m := make(map[string]bool)
	for _, entry := range entries {
		m[entry] = true
	}
	for _, link := range u.FrontendLinks {
		if _, exists := m[link]; exists {
			m[link] = false
		}
	}
	for _, entry := range entries {
		if m[entry] {
			u.FrontendLinks = append(u.FrontendLinks, entry)
		}
	}
	return nil
}

// GetClaimValueByField returns the value of the provides claims field.
func (u *User) GetClaimValueByField(k string) string {
	if u.mkv == nil {
		return ""
	}
	if v, exists := u.mkv[k]; exists {
		switch data := v.(type) {
		case string:
			return data
		case []string:
			return strings.Join(data, " ")
		default:
			return fmt.Sprintf("%v", data)
		}
	}
	return ""
}

// NewCheckpoints returns Checkpoint instances.
func NewCheckpoints(v interface{}) ([]*Checkpoint, error) {
	var entries []string
	checkpoints := []*Checkpoint{}
	switch data := v.(type) {
	case string:
		entries = append(entries, data)
	case []string:
		entries = data
	case []interface{}:
		for _, entry := range data {
			switch entry.(type) {
			case string:
				entries = append(entries, entry.(string))
			default:
				return nil, errors.ErrCheckpointInvalidType.WithArgs(data, data)
			}
		}
	default:
		return nil, errors.ErrCheckpointInvalidType.WithArgs(data, data)
	}
	for i, entry := range entries {
		c, err := NewCheckpoint(entry)
		if err != nil {
			return nil, errors.ErrCheckpointInvalidInput.WithArgs(entry, err)
		}
		c.ID = i
		checkpoints = append(checkpoints, c)
	}
	if len(checkpoints) < 1 {
		return nil, errors.ErrCheckpointEmpty
	}
	return checkpoints, nil
}

// NewCheckpoint returns Checkpoint instance.
func NewCheckpoint(s string) (*Checkpoint, error) {
	c := &Checkpoint{}
	args, err := cfgutils.DecodeArgs(s)
	if err != nil {
		return nil, err
	}
	if len(args) < 1 {
		return nil, fmt.Errorf("too short")
	}
	if args[0] == "require" {
		args = args[1:]
	}
	if len(args) < 1 {
		return nil, fmt.Errorf("too short")
	}

	switch args[0] {
	case "mfa":
		c.Name = "Multi-factor authentication"
		c.Type = "mfa"
	case "password":
		c.Name = "Authenticate with password"
		c.Type = "password"
	//case "consent":
	//	c.Name = "Acceptance and consent"
	//	c.Type = "consent"
	default:
		return nil, fmt.Errorf("unsupported keyword: %s", args[0])
	}
	return c, nil
}

func unpackUserData(data interface{}) (map[string]interface{}, error) {
	var m map[string]interface{}
	switch v := data.(type) {
	case string:
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return nil, err
		}
	case []uint8:
		if err := json.Unmarshal(v, &m); err != nil {
			return nil, err
		}
	case map[string]interface{}:
		m = v
	}

	if len(m) == 0 {
		return nil, errors.ErrInvalidUserDataType
	}
	return m, nil
}

func (c *Claims) unpackAudience(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch audiences := v.(type) {
	case string:
		c.Audience = append(c.Audience, audiences)
	case []interface{}:
		for _, audience := range audiences {
			switch audience.(type) {
			case string:
				c.Audience = append(c.Audience, audience.(string))
			default:
				return errors.ErrInvalidAudience.WithArgs(audience)
			}
		}
	case []string:
		for _, audience := range audiences {
			c.Audience = append(c.Audience, audience)
		}
	default:
		return errors.ErrInvalidAudienceType.WithArgs(v)
	}
	switch len(c.Audience) {
	case 0:
	case 1:
		tkv[k] = c.Audience
		mkv[k] = c.Audience[0]
	default:
		tkv[k] = c.Audience
		mkv[k] = c.Audience
	}
	return nil
}

func (c *Claims) unpackExpiresAt(k string, v interface{}, mkv map[string]interface{}) error {
	switch exp := v.(type) {
	case float64:
		c.ExpiresAt = int64(exp)
	case int:
		c.ExpiresAt = int64(exp)
	case int64:
		c.ExpiresAt = exp
	case json.Number:
		i, _ := exp.Int64()
		c.ExpiresAt = i
	default:
		return errors.ErrInvalidClaimExpiresAt.WithArgs(v)
	}
	mkv[k] = c.ExpiresAt
	return nil
}

func (c *Claims) unpackID(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch v.(type) {
	case string:
		c.ID = v.(string)
	default:
		return errors.ErrInvalidIDClaimType.WithArgs(v)
	}
	tkv[k] = c.ID
	mkv[k] = c.ID
	return nil
}

func (c *Claims) unpackIssuedAt(k string, v interface{}, mkv map[string]interface{}) error {
	switch exp := v.(type) {
	case float64:
		c.IssuedAt = int64(exp)
	case int:
		c.IssuedAt = int64(exp)
	case int64:
		c.IssuedAt = exp
	case json.Number:
		i, _ := exp.Int64()
		c.IssuedAt = i
	default:
		return errors.ErrInvalidClaimIssuedAt.WithArgs(v)
	}
	mkv[k] = c.IssuedAt
	return nil
}

func (c *Claims) unpackIssuer(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch v.(type) {
	case string:
		c.Issuer = v.(string)
	default:
		return errors.ErrInvalidIssuerClaimType.WithArgs(v)
	}
	tkv[k] = c.Issuer
	mkv[k] = c.Issuer
	return nil
}

func (c *Claims) unpackNotBefore(k string, v interface{}, mkv map[string]interface{}) error {
	switch exp := v.(type) {
	case float64:
		c.NotBefore = int64(exp)
	case int:
		c.NotBefore = int64(exp)
	case int64:
		c.NotBefore = exp
	case json.Number:
		i, _ := exp.Int64()
		c.NotBefore = i
	default:
		return errors.ErrInvalidClaimNotBefore.WithArgs(v)
	}
	mkv[k] = c.NotBefore
	return nil
}

func (c *Claims) unpackSubject(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch v.(type) {
	case string:
		c.Subject = v.(string)
	default:
		return errors.ErrInvalidSubjectClaimType.WithArgs(v)
	}
	tkv[k] = c.Subject
	mkv[k] = c.Subject
	return nil
}

func (c *Claims) unpackMail(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch v.(type) {
	case string:
		c.Email = v.(string)
	default:
		return errors.ErrInvalidEmailClaimType.WithArgs(k, v)
	}
	tkv["mail"] = c.Email
	mkv["mail"] = c.Email
	return nil
}

func (c *Claims) unpackName(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch names := v.(type) {
	case string:
		c.Name = names
	case []interface{}:
		packedNames := []string{}
		for _, n := range names {
			switch n.(type) {
			case string:
				packedNames = append(packedNames, n.(string))
			default:
				return errors.ErrInvalidNameClaimType.WithArgs(v)
			}
		}
		c.Name = strings.Join(packedNames, " ")
	default:
		return errors.ErrInvalidNameClaimType.WithArgs(v)
	}
	tkv[k] = c.Name
	mkv[k] = c.Name
	return nil
}

func (c *Claims) unpackRoles(v interface{}) error {
	switch roles := v.(type) {
	case []interface{}:
		for _, role := range roles {
			switch role.(type) {
			case string:
				c.Roles = append(c.Roles, role.(string))
			default:
				return errors.ErrInvalidRole.WithArgs(role)
			}
		}
	case []string:
		for _, role := range roles {
			c.Roles = append(c.Roles, role)
		}
	case string:
		for _, role := range strings.Split(roles, " ") {
			c.Roles = append(c.Roles, role)
		}
	default:
		return errors.ErrInvalidRoleType.WithArgs(v)
	}
	return nil
}

func (c *Claims) unpackScopes(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch scopes := v.(type) {
	case []interface{}:
		for _, scope := range scopes {
			switch scope.(type) {
			case string:
				c.Scopes = append(c.Scopes, scope.(string))
			default:
				return errors.ErrInvalidScope.WithArgs(scope)
			}
		}
	case []string:
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	case string:
		for _, scope := range strings.Split(scopes, " ") {
			c.Scopes = append(c.Scopes, scope)
		}
	default:
		return errors.ErrInvalidScopeType.WithArgs(v)
	}
	tkv["scopes"] = c.Scopes
	mkv["scopes"] = strings.Join(c.Scopes, " ")
	return nil
}

func (c *Claims) unpackOrg(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch orgs := v.(type) {
	case []interface{}:
		for _, org := range orgs {
			switch org.(type) {
			case string:
				c.Organizations = append(c.Organizations, org.(string))
			default:
				return errors.ErrInvalidOrg.WithArgs(org)
			}
		}
	case []string:
		for _, org := range orgs {
			c.Organizations = append(c.Organizations, org)
		}
	case string:
		for _, org := range strings.Split(orgs, " ") {
			c.Organizations = append(c.Organizations, org)
		}
	default:
		return errors.ErrInvalidOrgType.WithArgs(v)
	}
	tkv[k] = c.Organizations
	mkv[k] = strings.Join(c.Organizations, " ")
	return nil
}

func (c *Claims) unpackAddr(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch v.(type) {
	case string:
		c.Address = v.(string)
	default:
		return errors.ErrInvalidAddrType.WithArgs(v)
	}
	tkv[k] = c.Address
	mkv[k] = c.Address
	return nil
}

func (c *Claims) unpackOrigin(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch v.(type) {
	case string:
		c.Origin = v.(string)
	default:
		return errors.ErrInvalidOriginClaimType.WithArgs(v)
	}
	tkv[k] = c.Origin
	mkv[k] = c.Origin
	return nil
}

func (c *Claims) unpackPicture(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch v.(type) {
	case string:
		c.PictureURL = v.(string)
	default:
		return errors.ErrInvalidPictureClaimType.WithArgs(v)
	}
	mkv[k] = c.PictureURL
	return nil
}

func (c *Claims) unpackAppMetadata(v interface{}) error {
	switch v.(type) {
	case map[string]interface{}:
		appMetadata := v.(map[string]interface{})
		if _, authzExists := appMetadata["authorization"]; authzExists {
			switch appMetadata["authorization"].(type) {
			case map[string]interface{}:
				appMetadataAuthz := appMetadata["authorization"].(map[string]interface{})
				if _, rolesExists := appMetadataAuthz["roles"]; rolesExists {
					switch roles := appMetadataAuthz["roles"].(type) {
					case []interface{}:
						for _, role := range roles {
							switch role.(type) {
							case string:
								c.Roles = append(c.Roles, role.(string))
							default:
								return errors.ErrInvalidRole.WithArgs(role)
							}
						}
					case []string:
						for _, role := range roles {
							c.Roles = append(c.Roles, role)
						}
					default:
						return errors.ErrInvalidAppMetadataRoleType.WithArgs(appMetadataAuthz["roles"])
					}
				}
			}
		}
	}
	return nil
}

func (c *Claims) unpackRealmAccess(v interface{}) error {
	switch v.(type) {
	case map[string]interface{}:
		realmAccess := v.(map[string]interface{})
		if _, rolesExists := realmAccess["roles"]; rolesExists {
			switch roles := realmAccess["roles"].(type) {
			case []interface{}:
				for _, role := range roles {
					switch role.(type) {
					case string:
						c.Roles = append(c.Roles, role.(string))
					default:
						return errors.ErrInvalidRole.WithArgs(role)
					}
				}
			case []string:
				for _, role := range roles {
					c.Roles = append(c.Roles, role)
				}
			}
		}
	}
	return nil
}

func (c *Claims) unpackAccessListPaths(v interface{}) error {
	switch v.(type) {
	case []interface{}:
		paths := v.([]interface{})
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
				return errors.ErrInvalidAccessListPath.WithArgs(path)
			}
		}
	}
	return nil
}

func (c *Claims) unpackAccessList(v interface{}) error {
	switch v.(type) {
	case map[string]interface{}:
		acl := v.(map[string]interface{})
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
						return errors.ErrInvalidAccessListPath.WithArgs(path)
					}
				}
			}
		}
	}
	return nil
}

func (c *Claims) unpackMetadata(k string, v interface{}, mkv, tkv map[string]interface{}) error {
	switch v.(type) {
	case map[string]interface{}:
		c.Metadata = v.(map[string]interface{})
	default:
		return errors.ErrInvalidMetadataClaimType.WithArgs(v)
	}
	mkv[k] = c.Metadata
	return nil
}

// NewUser returns a user with associated standard and custom claims.
func NewUser(data interface{}) (*User, error) {
	u := &User{}
	m, unpackErr := unpackUserData(data)
	if unpackErr != nil {
		return nil, unpackErr
	}
	c := &Claims{}
	mkv := make(map[string]interface{})
	tkv := make(map[string]interface{})

	for k, v := range m {
		switch k {
		case "aud":
			if err := c.unpackAudience(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "exp":
			if err := c.unpackExpiresAt(k, v, mkv); err != nil {
				return nil, err
			}
		case "jti":
			if err := c.unpackID(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "iat":
			if err := c.unpackIssuedAt(k, v, mkv); err != nil {
				return nil, err
			}
		case "iss":
			if err := c.unpackIssuer(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "nbf":
			if err := c.unpackNotBefore(k, v, mkv); err != nil {
				return nil, err
			}
		case "sub":
			if err := c.unpackSubject(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "email", "mail":
			if err := c.unpackMail(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "name":
			if err := c.unpackName(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "roles", "role", "groups", "group":
			if err := c.unpackRoles(v); err != nil {
				return nil, err
			}
		case "scopes", "scope":
			if err := c.unpackScopes(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "org":
			if err := c.unpackOrg(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "addr":
			if err := c.unpackAddr(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "origin":
			if err := c.unpackOrigin(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "picture":
			if err := c.unpackPicture(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "app_metadata":
			if err := c.unpackAppMetadata(v); err != nil {
				return nil, err
			}
		case "realm_access":
			if err := c.unpackRealmAccess(v); err != nil {
				return nil, err
			}
		case "paths":
			if err := c.unpackAccessListPaths(v); err != nil {
				return nil, err
			}
		case "acl":
			if err := c.unpackAccessList(v); err != nil {
				return nil, err
			}
		case "metadata":
			if err := c.unpackMetadata(k, v, mkv, tkv); err != nil {
				return nil, err
			}
		case "frontend_links", "challenges":
		default:
			if c.custom == nil {
				c.custom = make(map[string]interface{})
			}
			c.custom[k] = v
			mkv[k] = v
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

	if len(c.Roles) == 0 {
		c.Roles = append(c.Roles, "anonymous")
		c.Roles = append(c.Roles, "guest")
	}

	if (len(c.Email) > 0) && (len(c.Name) > 0) {
		if strings.Contains(c.Name, c.Email) {
			c.Name = strings.TrimSpace(strings.ReplaceAll(c.Name, c.Email, ""))
			tkv["name"] = c.Name
			mkv["name"] = c.Name
		}
	}

	if len(c.Roles) > 0 {
		tkv["roles"] = c.Roles
		mkv["roles"] = c.Roles
	}

	u.rkv = make(map[string]interface{})
	for _, roleName := range c.Roles {
		u.rkv[roleName] = true
	}

	u.Claims = c
	u.mkv = mkv
	u.tkv = tkv
	return u, nil
}
