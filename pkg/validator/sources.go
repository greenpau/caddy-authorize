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
	"github.com/greenpau/caddy-auth-jwt/pkg/claims"
	"github.com/greenpau/caddy-auth-jwt/pkg/errors"
	"github.com/greenpau/caddy-auth-jwt/pkg/options"
	"net/http"
	"strings"
)

const (
	tokenSourceHeader = "header"
	tokenSourceCookie = "cookie"
	tokenSourceQuery  = "query"
)

var (
	defaultTokenNames = []string{
		"access_token",
		"jwt_access_token",
	}
	defaultTokenSourcePriority = map[string]int{
		tokenSourceHeader: 0,
		tokenSourceCookie: 1,
		tokenSourceQuery:  2,
	}
	defaultTokenSources []string
)

func init() {
	defaultTokenSources = make([]string, len(defaultTokenSourcePriority))
	for source, priority := range defaultTokenSourcePriority {
		defaultTokenSources[priority] = source
	}
}

func (v *TokenValidator) clearAuthSources() {
	v.clearAuthHeaders()
	v.clearAuthCookies()
	v.clearAuthQueryParams()
}

// clearAuthQueryParams clears source HTTP query parameters.
func (v *TokenValidator) clearAuthQueryParams() {
	v.authQueryParams = make(map[string]interface{})
}

// clearAuthHeaders clears source HTTP Authorization header.
func (v *TokenValidator) clearAuthHeaders() {
	v.authHeaders = make(map[string]interface{})
}

// clearAuthCookies clears source HTTP cookies.
func (v *TokenValidator) clearAuthCookies() {
	v.authCookies = make(map[string]interface{})
}

// parseQueryParams authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP query parameters.
func (v *TokenValidator) parseQueryParams(r *http.Request, opts *options.TokenValidatorOptions) (string, string) {
	values := r.URL.Query()
	if len(values) == 0 {
		return "", ""
	}
	for k := range v.authQueryParams {
		value := values.Get(k)
		if len(value) > 32 {
			return k, value
		}
	}
	return "", ""
}

// AuthorizeAuthorizationHeader authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP Authorization header.
func (v *TokenValidator) parseAuthHeader(r *http.Request, opts *options.TokenValidatorOptions) (string, string) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return "", ""
	}
	entries := strings.Split(hdr, ",")
	for _, entry := range entries {
		if opts != nil && opts.ValidateBearerHeader && strings.HasPrefix(entry, "Bearer") {
			// If JWT token as being passed as a bearer token
			// then, the token will not be a key-value pair.
			kv := strings.SplitN(entry, " ", 2)
			if len(kv) != 2 {
				continue
			}
			return "bearer", strings.TrimSpace(kv[1])
		}
		kv := strings.SplitN(entry, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		if _, exists := v.authHeaders[k]; exists {
			return k, strings.TrimSpace(kv[1])
		}
	}
	return "", ""
}

// AuthorizeCookies authorizes HTTP requests based on the presence and the
// content of the tokens in HTTP cookies.
func (v *TokenValidator) parseCookies(r *http.Request, opts *options.TokenValidatorOptions) (string, string) {
	for _, cookie := range r.Cookies() {
		if cookie == nil {
			continue
		}
		if _, exists := v.authCookies[cookie.Name]; !exists {
			continue
		}
		if len(cookie.Value) < 32 {
			continue
		}
		parts := strings.Split(strings.TrimSpace(cookie.Value), " ")
		return cookie.Name, strings.TrimSpace(parts[0])

	}
	return "", ""
}

// Authorize authorizes HTTP requests based on the presence and the content of
// the tokens in the requests.
func (v *TokenValidator) Authorize(r *http.Request, opts *options.TokenValidatorOptions) (*claims.UserClaims, string, error) {
	var token, tokenName string
	var found bool
	for _, sourceName := range v.tokenSources {
		switch sourceName {
		case tokenSourceHeader:
			tokenName, token = v.parseAuthHeader(r, opts)
		case tokenSourceCookie:
			tokenName, token = v.parseCookies(r, opts)
		case tokenSourceQuery:
			tokenName, token = v.parseQueryParams(r, opts)
		}
		if token != "" {
			found = true
			break
		}
	}
	if !found {
		return nil, "", errors.ErrNoTokenFound
	}
	userClaims, err := v.ValidateToken(token, opts)
	if err != nil {
		return nil, "", err
	}
	return userClaims, tokenName, nil
}
