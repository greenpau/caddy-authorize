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
	"net/http"
	"strings"

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

// SetAllowedTokenNames sets the names of the tokens evaluated
// by TokenValidator.
func (v *TokenValidator) SetAllowedTokenNames(arr []string) error {
	if len(arr) == 0 {
		return errors.ErrTokenNamesNotFound
	}
	m := make(map[string]bool)
	for _, s := range arr {
		s = strings.TrimSpace(s)
		if s == "" {
			return errors.ErrEmptyTokenName
		}
		if _, exists := m[s]; exists {
			return errors.ErrDuplicateTokenName.WithArgs(s)
		}
		m[s] = true
	}
	v.clearAuthSources()
	for _, s := range arr {
		v.authHeaders[s] = true
		v.authCookies[s] = true
		v.authQueryParams[s] = true
	}
	return nil
}

// SetSourcePriority sets the order in which various token sources are being
// evaluated for the presence of keys. The default order is cookie, header,
// and query parameters.
func (v *TokenValidator) SetSourcePriority(arr []string) error {
	if len(arr) == 0 || len(arr) > 3 {
		return errors.ErrInvalidSourcePriority
	}
	m := make(map[string]bool)
	for _, s := range arr {
		s = strings.TrimSpace(s)
		if s != tokenSourceHeader && s != tokenSourceCookie && s != tokenSourceQuery {
			return errors.ErrInvalidSourceName.WithArgs(s)
		}
		if _, exists := m[s]; exists {
			return errors.ErrDuplicateSourceName.WithArgs(s)
		}
		m[s] = true
	}
	v.tokenSources = arr
	return nil
}

// ValidateToken parses a token and returns claims, if any.
func (v *TokenValidator) ValidateToken(ctx context.Context, r *http.Request, s string, opts *options.TokenValidatorOptions) (*claims.UserClaims, error) {
	var uc *claims.UserClaims
	var err error
	// Perform cache lookup for the previously obtained credentials.
	uc = v.cache.Get(s)
	if uc == nil {
		// The user claims are not in the cache.
		uc, err = v.keystore.ParseToken(s)
		if err != nil {
			return nil, errors.ErrValidatorInvalidToken.WithArgs(err)
		}
	}

	if v.accessList == nil {
		return nil, errors.ErrNoAccessList
	}

	userData := uc.ExtractKV()
	if opts != nil {
		if opts.ValidateMethodPath {
			userData["method"] = r.Method
			userData["path"] = r.URL.Path
		}
	}

	if userAllowed := v.accessList.Allow(ctx, userData); !userAllowed {
		return nil, errors.ErrAccessNotAllowed
	}

	if opts == nil {
		return uc, nil
	}

	// Validate IP address embedded inside the evaluated token.
	// TODO(greenpau): the metadata will not have the address. Inject it to the context.
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
	// Validate requsted path against the Path-based ACL embedded inside the
	// evaluated token.
	if opts.ValidateAccessListPathClaim && uc.AccessList.Paths != nil {
		if len(uc.AccessList.Paths) > 0 {
			aclPathMatch := false
			for path := range uc.AccessList.Paths {
				if !acl.MatchPathBasedACL(path, r.URL.Path) {
					continue
				}
				aclPathMatch = true
				break
			}
			if !aclPathMatch {
				return nil, errors.ErrAccessNotAllowedByPathACL
			}
		}
	}
	return uc, nil
}

// AddAccessList adds ACL.
func (v *TokenValidator) AddAccessList(ctx context.Context, accessList *acl.AccessList) error {
	v.accessList = accessList
	return nil
}

// AddKeys adds keys for the verification of tokens.
func (v *TokenValidator) AddKeys(ctx context.Context, keys []*kms.Key) error {
	var count int
	if len(keys) == 0 {
		return errors.ErrValidatorKeystoreNoKeys
	}
	for _, k := range keys {
		if !k.Verify.Token.Capable {
			continue
		}
		if k.Verify.Token.Name == "" {
			continue
		}
		if k.Verify.Token.MaxLifetime == 0 {
			continue
		}
		v.keystore.AddKey(k)
		v.authHeaders[k.Name] = true
		v.authCookies[k.Name] = true
		v.authQueryParams[k.Name] = true
		count++
	}
	if count == 0 {
		return errors.ErrValidatorKeystoreNoVerifyKeys
	}

	return nil
}
