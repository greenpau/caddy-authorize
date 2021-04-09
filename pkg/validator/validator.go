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
	"context"
	"time"

	"github.com/greenpau/caddy-auth-jwt/pkg/acl"
	"github.com/greenpau/caddy-auth-jwt/pkg/cache"
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
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
	accessList      *acl.AccessList
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

// ValidateToken parses a token and returns claims, if any.
func (v *TokenValidator) ValidateToken(ctx context.Context, s string, opts *options.TokenValidatorOptions) (*claims.UserClaims, error) {
	var uc *claims.UserClaims
	var err error
	// Perform cache lookup for the previously obtained credentials.
	uc = v.cache.Get(s)
	if uc != nil {
		// The user claims are in the cache.
		if uc.ExpiresAt < time.Now().Unix() {
			v.cache.Delete(s)
			return nil, errors.ErrExpiredToken
		}
	} else {
		// The user claims are not in the cache.
		uc, err = v.keystore.ParseToken(s)
		if err != nil {
			return nil, errors.ErrValidatorInvalidToken.WithArgs(err)
		}
	}

	if v.accessList == nil {
		return nil, errors.ErrNoAccessList
	}

	userData := uc.AsMap()
	if err := v.accessList.Allow(ctx, userData); err != nil {
		return err
	}

	if opts == nil {
		return uc, nil
	}

	// IP validation based on the provided options
	if opts.ValidateSourceAddress && opts.Metadata != nil {
		if uc.Address == "" {
			return nil, errors.ErrSourceAddressNotFound
		}
		if reqAddr, exists := opts.Metadata["address"]; exists {
			if uc.Address != reqAddr.(string) {
				return nil, errors.ErrSourceAddressMismatch.WithArgs(uc.Address, reqAddr.(string))
			}
		}
	}
	// Path-based ACL validation
	if opts.ValidateAccessListPathClaim && opts.Metadata != nil {
		if uc.AccessList.Paths != nil {
			if len(uc.AccessList.Paths) > 0 {
				aclPathMatch := false
				if reqPath, exists := opts.Metadata["path"]; exists {
					for path := range uc.AccessList.Paths {
						if !acl.MatchPathBasedACL(path, reqPath.(string)) {
							continue
						}
						aclPathMatch = true
						break
					}
				}
				if !aclPathMatch {
					return nil, errors.ErrAccessNotAllowedByPathACL
				}
			}
		}
	}
	return uc, nil
}

// AddAccessList adds ACL.
func (v *TokenValidator) AddAccessList(accessList *acl.AccessList) error {
	v.accessList = accessList
	return nil
}
