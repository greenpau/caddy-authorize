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

package acl

import (
	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"regexp"
	"strings"
)

var pathACLPatterns map[string]*regexp.Regexp

func init() {
	pathACLPatterns = make(map[string]*regexp.Regexp)
}

// AccessListEntry represent an access list entry.
type AccessListEntry struct {
	Action  string   `json:"action,omitempty"`
	Values  []string `json:"values,omitempty"`
	Claim   string   `json:"claim,omitempty"`
	Methods []string `json:"method,omitempty"`
	Path    string   `json:"path,omitempty"`
}

// NewAccessListEntry return an instance of AccessListEntry.
func NewAccessListEntry() *AccessListEntry {
	return &AccessListEntry{}
}

// Validate checks access list entry compliance
func (acl *AccessListEntry) Validate() error {
	if acl.Action == "" {
		return errors.ErrEmptyACLAction
	}
	if acl.Action != "allow" && acl.Action != "deny" {
		return errors.ErrUnsupportedACLAction.WithArgs(acl.Action)
	}
	if acl.Claim == "" {
		return errors.ErrEmptyACLClaim
	}
	if len(acl.Values) == 0 {
		return errors.ErrNoValues
	}
	return nil
}

// Allow sets action to allow in an access list entry.
func (acl *AccessListEntry) Allow() {
	acl.Action = "allow"
	return
}

// Deny sets action to deny in an access list entry.
func (acl *AccessListEntry) Deny() {
	acl.Action = "deny"
	return
}

// SetAction sets action in an access list entry.
func (acl *AccessListEntry) SetAction(s string) error {
	if s == "" {
		return errors.ErrEmptyACLAction
	}
	if s != "allow" && s != "deny" {
		return errors.ErrUnsupportedACLAction.WithArgs(s)
	}
	acl.Action = s
	return nil
}

// SetClaim sets claim value of an access list entry.
func (acl *AccessListEntry) SetClaim(s string) error {
	supportedClaims := map[string]string{
		"roles":  "roles",
		"role":   "roles",
		"groups": "roles",
		"group":  "roles",
	}
	if s == "" {
		return errors.ErrEmptyClaim
	}
	if _, exists := supportedClaims[s]; !exists {
		return errors.ErrUnsupportedClaim.WithArgs(s)
	}
	acl.Claim = supportedClaims[s]
	return nil
}

// AddMethod adds http method to an access list entry.
func (acl *AccessListEntry) AddMethod(s string) error {
	if s == "" {
		return errors.ErrEmptyMethod
	}
	s = strings.ToUpper(s)
	switch s {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
	default:
		return errors.ErrUnsupportedMethod.WithArgs(s)
	}
	acl.Methods = append(acl.Methods, s)
	return nil
}

// SetPath sets http path substring to an access list entry.
func (acl *AccessListEntry) SetPath(s string) error {
	if s == "" {
		return errors.ErrEmptyPath
	}
	acl.Path = s
	return nil
}

// AddValue adds value to an access list entry.
func (acl *AccessListEntry) AddValue(s string) error {
	if s == "" {
		return errors.ErrEmptyValue
	}
	acl.Values = append(acl.Values, s)
	return nil
}

// SetValue sets value to an access list entry.
func (acl *AccessListEntry) SetValue(arr []string) error {
	if len(arr) == 0 {
		return errors.ErrEmptyValue
	}
	acl.Values = arr
	return nil
}

// GetAction returns access list entry action.
func (acl *AccessListEntry) GetAction() string {
	return acl.Action
}

// GetClaim returns access list entry claim name.
func (acl *AccessListEntry) GetClaim() string {
	return acl.Claim
}

// GetValues returns access list entry claim values.
func (acl *AccessListEntry) GetValues() string {
	return strings.Join(acl.Values, " ")
}

// IsClaimAllowed checks whether access list entry allows the claims.
func (acl *AccessListEntry) IsClaimAllowed(userClaims *jwtclaims.UserClaims, opts *jwtconfig.TokenValidatorOptions) (bool, bool) {
	claimMatches := false
	methodMatches := false
	pathMatches := false
	switch acl.Claim {
	case "roles":
		if len(userClaims.Roles) == 0 {
			return false, false
		}
		for _, role := range userClaims.Roles {
			if claimMatches {
				break
			}
			for _, value := range acl.Values {
				if value == role || value == "*" || value == "any" {
					claimMatches = true
					break
				}
			}
		}
	default:
		return false, false
	}

	if opts != nil {
		if opts.ValidateMethodPath && opts.Metadata != nil {
			// The opts.Metadata shoud contain method and path keys
			if len(acl.Methods) < 1 {
				methodMatches = true
			} else {
				// Match HTTP Request Method
				if reqMethod, exists := opts.Metadata["method"]; exists {
					for _, method := range acl.Methods {
						if reqMethod.(string) == method {
							methodMatches = true
							break
						}
					}
				} else {
					methodMatches = true
				}
			}

			if acl.Path == "" {
				pathMatches = true
			} else {
				// Match HTTP Request URI
				if reqPath, exists := opts.Metadata["path"]; exists {
					if strings.Contains(reqPath.(string), acl.Path) {
						pathMatches = true
					}
				} else {
					pathMatches = true
				}
			}
		} else {
			methodMatches = true
			pathMatches = true
		}
	} else {
		methodMatches = true
		pathMatches = true
	}

	if claimMatches && methodMatches && pathMatches {
		if acl.Action == "allow" {
			return true, false
		}
		return false, true
	}
	return false, false
}

// MatchPathBasedACL matches pattern in a URI.
func MatchPathBasedACL(pattern, uri string) bool {
	// First, handle the case where there are no wildcards
	if pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		if pattern == uri {
			return true
		}
		return false
	}

	// Next, handle the case where wildcards are present
	var regex *regexp.Regexp
	var found bool

	// Check cached entries
	regex, found = pathACLPatterns[pattern]
	if !found {
		// advPattern = strings.ReplaceAll(pattern, "/", "\\/")
		advPattern := strings.ReplaceAll(pattern, "**", "[a-zA-Z0-9_/.~-]+")
		advPattern = strings.ReplaceAll(advPattern, "*", "[a-zA-Z0-9_.~-]+")
		advPattern = "^" + advPattern + "$"
		r, err := regexp.Compile(advPattern)
		if err != nil {
			pathACLPatterns[pattern] = nil
			return false
		}
		pathACLPatterns[pattern] = r
		regex = r
	}
	if regex == nil {
		return false
	}

	return regex.MatchString(uri)
}
