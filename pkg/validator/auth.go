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
	// "github.com/greenpau/caddy-authorize/pkg/user"
	"github.com/greenpau/caddy-authorize/pkg/shared/idp"
	addrutils "github.com/greenpau/caddy-authorize/pkg/utils/addr"
	"net/http"
	"strings"
)

type authToken struct {
	Secret string
	Realm  string
	Source string
	Name   string
	Value  string
	Found  bool
	Error  error
}

// parseCustomAuthHeader authorizes HTTP requests based on the presence and the
// content of HTTP Authorization or X-API-Key headers.
func (v *TokenValidator) parseCustomAuthHeader(ctx context.Context, r *http.Request) *authToken {
	token := &authToken{}
	if v.basicAuthEnabled {
		v.parseCustomBasicAuthHeader(ctx, r, token)
	}
	if !token.Found && v.apiKeyAuthEnabled {
		v.parseCustomAPIKeyAuthHeader(ctx, r, token)
	}
	return token
}

func (v *TokenValidator) parseCustomBasicAuthHeader(ctx context.Context, r *http.Request, token *authToken) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return
	}
	entries := strings.Split(hdr, ",")
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if !strings.HasPrefix(entry, "Basic") {
			continue
		}
		entry = strings.TrimPrefix(entry, "Basic")
		entry = strings.TrimSpace(entry)
		token.Source = "basicauth"
		token.Name = "Basic"
		token.Found = true
		sep := strings.Index(entry, " ")
		if sep < 0 {
			token.Secret = entry
		} else {
			token.Secret = entry[:sep]
			directives := parseAuthHeaderDirectives(entry[sep+1:])
			if directives != nil {
				if realm, exists := directives["realm"]; exists {
					token.Realm = realm
				}
			}
		}
		break
	}

	if token.Found {
		if token.Realm != "" {
			// Check if the realm is registered.
			if _, exists := v.idpConfig.BasicAuth.Realms[token.Realm]; !exists {
				token.Error = errors.ErrBasicAuthFailed
				return
			}
		}

		idpr := &idp.ProviderRequest{
			Address: addrutils.GetSourceAddress(r),
			Context: v.idpConfig.Context,
			Realm:   token.Realm,
			Secret:  token.Secret,
		}
		if err := idp.Catalog.BasicAuth(idpr); err != nil {
			token.Error = err
		}
		token.Value = idpr.Response.Payload
	}
}

func (v *TokenValidator) parseCustomAPIKeyAuthHeader(ctx context.Context, r *http.Request, token *authToken) {
	hdr := r.Header.Get("X-API-Key")
	if hdr == "" {
		return
	}
	entry := strings.TrimSpace(hdr)
	token.Source = "apikey"
	token.Name = "X-API-Key"
	token.Found = true
	sep := strings.Index(entry, " ")
	if sep < 0 {
		token.Secret = entry
	} else {
		token.Secret = entry[:sep]
		directives := parseAuthHeaderDirectives(entry[sep+1:])
		if directives != nil {
			if realm, exists := directives["realm"]; exists {
				token.Realm = realm
			}
		}
	}

	if token.Realm != "" {
		// Check if the realm is registered.
		if _, exists := v.idpConfig.APIKeyAuth.Realms[token.Realm]; !exists {
			token.Error = errors.ErrAPIKeyAuthFailed
			return
		}
	}

	idpr := &idp.ProviderRequest{
		Address: addrutils.GetSourceAddress(r),
		Context: v.idpConfig.Context,
		Realm:   token.Realm,
		Secret:  token.Secret,
	}
	if err := idp.Catalog.APIKeyAuth(idpr); err != nil {
		token.Error = err
		return
	}
	token.Value = idpr.Response.Payload
}

func parseAuthHeaderDirectives(s string) map[string]string {
	m := make(map[string]string)
	for _, entry := range strings.Split(s, ",") {
		kv := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(kv) != 2 {
			continue
		}
		m[kv[0]] = strings.Trim(kv[1], `"'`)
	}
	return m
}
