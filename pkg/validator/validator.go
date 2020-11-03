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
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwtlib "github.com/dgrijalva/jwt-go"
	jwtacl "github.com/greenpau/caddy-auth-jwt/pkg/acl"
	jwtbackends "github.com/greenpau/caddy-auth-jwt/pkg/backends"
	jwtcache "github.com/greenpau/caddy-auth-jwt/pkg/cache"
	jwtclaims "github.com/greenpau/caddy-auth-jwt/pkg/claims"
	jwtconfig "github.com/greenpau/caddy-auth-jwt/pkg/config"
	jwterrors "github.com/greenpau/caddy-auth-jwt/pkg/errors"
)

const (
	tokenSourceHeader = "header"
	tokenSourceCookie = "cookie"
	tokenSourceQuery  = "query"
)

// TokenSources is the map containing token source priorities.
var TokenSources = map[string]byte{
	tokenSourceHeader: 0, // the value is the order they are in...
	tokenSourceCookie: 1,
	tokenSourceQuery:  2,
}

// AllTokenSources is the list of token sources.
var AllTokenSources []string

func init() { // set the default token_sources up
	AllTokenSources = make([]string, len(TokenSources))
	for k, v := range TokenSources {
		AllTokenSources[int(v)] = k
	}
}

var defaultTokenNames = []string{"access_token", "jwt_access_token"}

// TokenValidator validates tokens in http requests.
type TokenValidator struct {
	TokenConfigs         []*jwtconfig.CommonTokenConfig
	AuthorizationHeaders map[string]struct{}
	Cookies              map[string]struct{}
	QueryParameters      map[string]struct{}
	Cache                *jwtcache.TokenCache
	AccessList           []*jwtacl.AccessListEntry
	TokenBackends        []jwtbackends.TokenBackend
	TokenSources         []string
}

// NewTokenValidator returns an instance of TokenValidator
func NewTokenValidator() *TokenValidator {
	v := &TokenValidator{
		AuthorizationHeaders: make(map[string]struct{}),
		Cookies:              make(map[string]struct{}),
		QueryParameters:      make(map[string]struct{}),
		TokenConfigs:         []*jwtconfig.CommonTokenConfig{},
	}

	for _, name := range defaultTokenNames {
		v.AuthorizationHeaders[name] = struct{}{}
		v.Cookies[name] = struct{}{}
		v.QueryParameters[name] = struct{}{}
	}

	v.Cache = jwtcache.NewTokenCache()
	v.TokenSources = AllTokenSources
	return v
}

// OverwriteTokenName sets the name of the token (i.e. <TokenName>=<JWT Token>)
// this overrites the default token names
func (v *TokenValidator) OverwriteTokenName(name string) {
	v.AuthorizationHeaders = map[string]struct{}{name: {}}
	v.Cookies = map[string]struct{}{name: {}}
	v.QueryParameters = map[string]struct{}{name: {}}
}

// SetTokenName sets the name of the token (i.e. <TokenName>=<JWT Token>)
func (v *TokenValidator) SetTokenName(name string) {
	v.AuthorizationHeaders[name] = struct{}{}
	v.Cookies[name] = struct{}{}
	v.QueryParameters[name] = struct{}{}
}

// ConfigureTokenBackends configures available TokenBackend.
func (v *TokenValidator) ConfigureTokenBackends() error {
	v.TokenBackends = []jwtbackends.TokenBackend{}

	for _, c := range v.TokenConfigs {
		if c.TokenSecret != "" {
			backend, err := jwtbackends.NewSecretKeyTokenBackend(c.TokenSecret)
			if err != nil {
				return jwterrors.ErrInvalidSecret.WithArgs(err)
			}
			v.TokenBackends = append(v.TokenBackends, backend)
			continue
		}
		if err := LoadEncryptionKeys(c); err != nil {
			return err
		}

		tokenKeys := c.GetTokenKeys()
		if tokenKeys != nil {
			backend := jwtbackends.NewRSAKeyTokenBackend(tokenKeys)
			v.TokenBackends = append(v.TokenBackends, backend)
		}
	}
	if len(v.TokenBackends) == 0 {
		return jwterrors.ErrNoBackends
	}
	return nil
}

// ClearAuthorizationHeaders clears source HTTP Authorization header.
func (v *TokenValidator) ClearAuthorizationHeaders() {
	v.AuthorizationHeaders = make(map[string]struct{})
}

// ClearCookies clears source HTTP cookies.
func (v *TokenValidator) ClearCookies() {
	v.Cookies = make(map[string]struct{})
}

// ClearQueryParameters clears source HTTP query parameters.
func (v *TokenValidator) ClearQueryParameters() {
	v.QueryParameters = make(map[string]struct{})
}

// ClearAllSources clears all sources of token data
func (v *TokenValidator) ClearAllSources() {
	v.ClearAuthorizationHeaders()
	v.ClearCookies()
	v.ClearQueryParameters()
}

// Authorize authorizes HTTP requests based on the presence and the
// content of the tokens in the request.
func (v *TokenValidator) Authorize(r *http.Request, opts *jwtconfig.TokenValidatorOptions) (claims *jwtclaims.UserClaims, valid bool, err error) {
	for _, sourceName := range v.TokenSources { // check the source in the order of the slice
		switch sourceName {
		case tokenSourceHeader:
			if claims, valid, err = v.AuthorizeAuthorizationHeader(r, opts); valid || (err != nil && !errors.Is(err, jwterrors.ErrNoTokenFound)) {
				return claims, valid, err
			}
		case tokenSourceCookie:
			if claims, valid, err = v.AuthorizeCookies(r, opts); valid || (err != nil && !errors.Is(err, jwterrors.ErrNoTokenFound)) {
				return claims, valid, err
			}
		case tokenSourceQuery:
			if claims, valid, err = v.AuthorizeQueryParameters(r, opts); valid || (err != nil && !errors.Is(err, jwterrors.ErrNoTokenFound)) {
				return claims, valid, err
			}
		}
	}

	return claims, valid, err
}

// AuthorizeAuthorizationHeader authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP Authorization header.
func (v *TokenValidator) AuthorizeAuthorizationHeader(r *http.Request, opts *jwtconfig.TokenValidatorOptions) (u *jwtclaims.UserClaims, ok bool, err error) {
	authzHeaderStr := r.Header.Get("Authorization")
	if authzHeaderStr != "" && len(v.AuthorizationHeaders) > 0 {
		if token, found := v.SearchAuthorizationHeader(authzHeaderStr, opts); found {
			return v.ValidateToken(token, opts)
		}
		err = jwterrors.ErrNoTokenFound
	}
	return u, ok, err
}

// AuthorizeCookies authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP cookies.
func (v *TokenValidator) AuthorizeCookies(r *http.Request, opts *jwtconfig.TokenValidatorOptions) (u *jwtclaims.UserClaims, ok bool, err error) {
	// Second, check cookies
	cookies := r.Cookies()
	if len(cookies) > 0 && len(v.Cookies) > 0 {
		if token, found := v.SearchCookies(cookies); found {
			return v.ValidateToken(token, opts)
		}
		err = jwterrors.ErrNoTokenFound
	}
	return u, ok, err
}

// AuthorizeQueryParameters authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP query parameters.
func (v *TokenValidator) AuthorizeQueryParameters(r *http.Request, opts *jwtconfig.TokenValidatorOptions) (u *jwtclaims.UserClaims, ok bool, err error) {
	queryValues := r.URL.Query()
	if len(queryValues) > 0 && len(v.QueryParameters) > 0 {
		if token, found := v.SearchQueryValues(queryValues); found {
			return v.ValidateToken(token, opts)
		}
		err = jwterrors.ErrNoTokenFound
	}
	return u, ok, err
}

// ValidateToken parses a token and returns claims, if valid.
func (v *TokenValidator) ValidateToken(s string, opts *jwtconfig.TokenValidatorOptions) (*jwtclaims.UserClaims, bool, error) {
	valid := false
	// First, check cached entries
	claims := v.Cache.Get(s)
	if claims != nil {
		if claims.ExpiresAt < time.Now().Unix() {
			v.Cache.Delete(s)
			return nil, false, jwterrors.ErrExpiredToken
		}
		valid = true
	}

	errorMessages := []string{}
	// If not valid, parse claims from a string.
	if !valid {
		for _, backend := range v.TokenBackends {
			token, err := jwtlib.Parse(s, backend.ProvideKey)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}
			if !token.Valid {
				continue
			}
			claims, err = jwtclaims.ParseClaims(token)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}
			if claims == nil {
				errorMessages = append(errorMessages, "claims is nil")
				continue
			}
			valid = true
			break
		}
	}

	if valid {
		if len(v.AccessList) == 0 {
			return nil, false, jwterrors.ErrNoAccessList
		}
		aclAllowed := false
		for _, entry := range v.AccessList {
			claimAllowed, abortProcessing := entry.IsClaimAllowed(claims, opts)
			if abortProcessing {
				aclAllowed = claimAllowed
				break
			}
			if claimAllowed {
				aclAllowed = true
			}
		}
		if !aclAllowed {
			return nil, false, jwterrors.ErrAccessNotAllowed
		}

		if opts != nil {
			// IP validation based on the provided options
			if opts.ValidateSourceAddress && opts.Metadata != nil {
				if claims.Address == "" {
					return nil, false, jwterrors.ErrSourceAddressNotFound
				}
				if reqAddr, exists := opts.Metadata["address"]; exists {
					if claims.Address != reqAddr.(string) {
						return nil, false, jwterrors.ErrSourceAddressMismatch.WithArgs(claims.Address, reqAddr.(string))
					}
				}
			}
			// Path-based ACL validation
			if opts.ValidateAccessListPathClaim && opts.Metadata != nil {
				if claims.AccessList.Paths != nil {
					if len(claims.AccessList.Paths) > 0 {
						aclPathMatch := false
						if reqPath, exists := opts.Metadata["path"]; exists {
							for path := range claims.AccessList.Paths {
								if !jwtacl.MatchPathBasedACL(path, reqPath.(string)) {
									continue
								}
								aclPathMatch = true
								break
							}
						}
						if !aclPathMatch {
							return nil, false, jwterrors.ErrAccessNotAllowedByPathACL
						}
					}
				}
			}
		}
	}

	if !valid {
		return nil, false, jwterrors.ErrInvalid.WithArgs(errorMessages)
	}

	return claims, true, nil
}

// SearchAuthorizationHeader searches for tokens in the authorization header of
// HTTP requests.
func (v *TokenValidator) SearchAuthorizationHeader(s string, opts *jwtconfig.TokenValidatorOptions) (string, bool) {
	if len(v.AuthorizationHeaders) == 0 || s == "" {
		return "", false
	}
	header := strings.Split(s, ",")
	for _, entry := range header {
		if opts != nil && opts.ValidateBearerHeader && strings.HasPrefix(entry, "Bearer") {
			// If JWT token as being passed as a bearer token
			// then, the token will not be a key-value pair.
			kv := strings.SplitN(entry, " ", 2)
			if len(kv) != 2 {
				continue
			}
			return strings.TrimSpace(kv[1]), true
		}
		kv := strings.SplitN(entry, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		if _, exists := v.AuthorizationHeaders[k]; exists {
			return strings.TrimSpace(kv[1]), true
		}
	}
	return "", false
}

// SearchCookies searches for tokens in the cookies of HTTP requests.
func (v *TokenValidator) SearchCookies(cookies []*http.Cookie) (string, bool) {
	if len(cookies) == 0 || len(v.Cookies) == 0 {
		return "", false
	}
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}
		if _, exists := v.Cookies[cookie.Name]; exists {
			if len(cookie.Value) > 32 {
				token := strings.TrimSpace(cookie.Value)
				arr := strings.Split(token, " ")
				token = arr[0]
				return token, true
			}
		}
	}
	return "", false
}

// SearchQueryValues searches for tokens in the values of query parameters of
// HTTP requests.
func (v *TokenValidator) SearchQueryValues(params url.Values) (string, bool) {
	if len(v.QueryParameters) == 0 || len(params) == 0 {
		return "", false
	}

	for k := range v.QueryParameters {
		value := params.Get(k)
		if len(value) > 32 {
			return strings.TrimSpace(value), true
		}
	}

	return "", false
}
