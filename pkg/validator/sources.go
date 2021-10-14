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

package validator

import (
	"context"
	"github.com/greenpau/caddy-authorize/pkg/errors"
	"github.com/greenpau/caddy-authorize/pkg/user"
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
		tokenSourceCookie: 0,
		tokenSourceHeader: 1,
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
func (v *TokenValidator) parseQueryParams(ctx context.Context, r *http.Request) (string, string) {
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
func (v *TokenValidator) parseAuthHeader(ctx context.Context, r *http.Request) (string, string) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return "", ""
	}
	entries := strings.Split(hdr, ",")
	for _, entry := range entries {
		if v.opts.ValidateBearerHeader && strings.HasPrefix(entry, "Bearer") {
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
func (v *TokenValidator) parseCookies(ctx context.Context, r *http.Request) (string, string) {
	for _, cookie := range r.Cookies() {
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
func (v *TokenValidator) Authorize(ctx context.Context, r *http.Request) (usr *user.User, err error) {
	var token, tokenName, tokenSource string
	var found bool
	for _, sourceName := range v.tokenSources {
		switch sourceName {
		case tokenSourceHeader:
			tokenName, token = v.parseAuthHeader(ctx, r)
			tokenSource = tokenSourceHeader
		case tokenSourceCookie:
			tokenName, token = v.parseCookies(ctx, r)
			tokenSource = tokenSourceCookie
		case tokenSourceQuery:
			tokenName, token = v.parseQueryParams(ctx, r)
			tokenSource = tokenSourceQuery
		}
		if token != "" {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.ErrNoTokenFound
	}

	// Perform cache lookup for the previously obtained credentials.
	usr = v.cache.Get(token)
	if usr == nil {
		// The user is not in the cache.
		usr, err = v.keystore.ParseToken(tokenName, token)
		if err != nil {
			return usr, errors.ErrValidatorInvalidToken.WithArgs(err)
		}
	}

	if err := v.guardian.authorize(ctx, r, usr); err != nil {
		return usr, err
	}
	usr.TokenSource = tokenSource
	usr.TokenName = tokenName
	usr.Token = token
	return usr, nil
}
