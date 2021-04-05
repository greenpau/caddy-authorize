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

package validator

import (
	"net/http"
	"strings"
	"time"

	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/cache"
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/kms"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
)

// TokenValidator validates tokens in http requests.
type TokenValidator struct {
	keystore        *kms.Keystore
	authHeaders     map[string]interface{}
	authCookies     map[string]interface{}
	authQueryParams map[string]interface{}
	cache           *cache.TokenCache
	accessList      []*acl.AccessListEntry
	tokenSources    []string
}

// NewTokenValidator returns an instance of TokenValidator
func NewTokenValidator() *TokenValidator {
	v := &TokenValidator{
		keystore:        kms.NewKeystore(),
		authHeaders:     make(map[string]interface{}),
		authCookies:     make(map[string]interface{}),
		authQueryParams: make(map[string]interface{}),
	}

	for _, name := range defaultTokenNames {
		v.authHeaders[name] = true
		v.authCookies[name] = true
		v.authQueryParams[name] = true
	}

	v.cache = cache.NewTokenCache()
	// TODO(greenpau): really?
	v.tokenSources = defaultTokenSources
	return v
}

// Authorize authorizes HTTP requests based on the presence and the content of
// the tokens in the requests.
func (v *TokenValidator) Authorize(r *http.Request, opts *options.TokenValidatorOptions) (*claims.UserClaims, error) {
	var token string
	var found bool
	for _, sourceName := range v.tokenSources {
		switch sourceName {
		case tokenSourceHeader:
			token = v.parseAuthHeader(r, opts)
		case tokenSourceCookie:
			token = v.parseCookies(r, opts)
		case tokenSourceQuery:
			token = v.parseQueryParams(r, opts)
		}
		token = strings.TrimSpace(token)
		if token != "" {
			found = true
			break
		}
	}
	if !found {
		return nil, jwterrors.ErrNoTokenFound
	}
	return v.ValidateToken(token, opts)
}

// ValidateToken parses a token and returns claims, if any.
func (v *TokenValidator) ValidateToken(s string, opts *options.TokenValidatorOptions) (*claims.UserClaims, error) {
	var userClaims *claims.UserClaims
	var err error
	// Perform cache lookup for the previously obtained credentials.
	userClaims = v.cache.Get(s)
	if userClaims != nil {
		// The user claims are in the cache.
		if userClaims.ExpiresAt < time.Now().Unix() {
			v.cache.Delete(s)
			return nil, jwterrors.ErrExpiredToken
		}
	} else {
		// The user claims are not in the cache.
		userClaims, err = v.keystore.ParseToken(s)
		if err != nil {
			return nil, jwterrors.ErrValidatorInvalidToken.WithArgs(err)
		}
	}

	if len(v.accessList) == 0 {
		return nil, jwterrors.ErrNoAccessList
	}
	aclAllowed := false
	for _, entry := range v.accessList {
		claimAllowed, abortProcessing := entry.IsClaimAllowed(userClaims, opts)
		if abortProcessing {
			aclAllowed = claimAllowed
			break
		}
		if claimAllowed {
			aclAllowed = true
		} else if entry.Action == "allow" && opts.ValidateAllowMatchAll {
			aclAllowed = false
			break
		}
	}
	if !aclAllowed {
		return nil, jwterrors.ErrAccessNotAllowed
	}

	if opts == nil {
		return userClaims, nil
	}

	// IP validation based on the provided options
	if opts.ValidateSourceAddress && opts.Metadata != nil {
		if userClaims.Address == "" {
			return nil, jwterrors.ErrSourceAddressNotFound
		}
		if reqAddr, exists := opts.Metadata["address"]; exists {
			if userClaims.Address != reqAddr.(string) {
				return nil, jwterrors.ErrSourceAddressMismatch.WithArgs(userClaims.Address, reqAddr.(string))
			}
		}
	}
	// Path-based ACL validation
	if opts.ValidateAccessListPathClaim && opts.Metadata != nil {
		if userClaims.AccessList.Paths != nil {
			if len(userClaims.AccessList.Paths) > 0 {
				aclPathMatch := false
				if reqPath, exists := opts.Metadata["path"]; exists {
					for path := range userClaims.AccessList.Paths {
						if !acl.MatchPathBasedACL(path, reqPath.(string)) {
							continue
						}
						aclPathMatch = true
						break
					}
				}
				if !aclPathMatch {
					return nil, jwterrors.ErrAccessNotAllowedByPathACL
				}
			}
		}
	}
	return userClaims, nil
}

// AddAccessList adds ACL.
func (v *TokenValidator) AddAccessList(entries []*acl.AccessListEntry) error {
	v.accessList = entries
	return nil
}
