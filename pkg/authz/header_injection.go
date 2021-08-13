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

package authz

import (
	"fmt"
	"github.com/greenpau/caddy-auth-jwt/pkg/user"
	"net/http"
	"strings"
)

// HeaderInjectionConfig contains the entry for the authorization bypass.
type HeaderInjectionConfig struct {
	Header string `json:"header,omitempty" xml:"header,omitempty" yaml:"header,omitempty"`
	Field  string `json:"field,omitempty" xml:"field,omitempty" yaml:"field,omitempty"`
}

// Validate validates HeaderInjectionConfig
func (c *HeaderInjectionConfig) Validate() error {
	c.Header = strings.TrimSpace(c.Header)
	c.Field = strings.TrimSpace(c.Field)
	if c.Header == "" {
		return fmt.Errorf("undefined header name")
	}
	if c.Field == "" {
		return fmt.Errorf("undefined field name")
	}
	return nil
}

func (m *Authorizer) injectHeaders(r *http.Request, usr *user.User) {
	if m.PassClaimsWithHeaders {
		// Inject default X-Token headers.
		headers := usr.GetRequestHeaders()
		if headers == nil {
			headers = make(map[string]string)
			if usr.Claims.Name != "" {
				headers["X-Token-User-Name"] = usr.Claims.Name
			}
			if usr.Claims.Email != "" {
				headers["X-Token-User-Email"] = usr.Claims.Email
			}
			if len(usr.Claims.Roles) > 0 {
				headers["X-Token-User-Roles"] = strings.Join(usr.Claims.Roles, " ")
			}
			if usr.Claims.Subject != "" {
				headers["X-Token-Subject"] = usr.Claims.Subject
			}
			usr.SetRequestHeaders(headers)
		}

		for k, v := range headers {
			if m.injectedHeaders != nil {
				if _, exists := m.injectedHeaders[k]; exists {
					continue
				}
			}
			r.Header.Set(k, v)
		}
	}

	if m.injectedHeaders != nil {
		// Inject custom headers.
		for _, entry := range m.HeaderInjectionConfigs {
			if v := usr.GetClaimValueByField(entry.Field); v != "" {
				r.Header.Set(entry.Header, v)
			}
		}
	}
}

func (m *Authorizer) stripAuthToken(r *http.Request, usr *user.User) {
	if !m.StripTokenEnabled {
		return
	}
	switch usr.TokenSource {
	case "cookie":
		if usr.TokenName != "" {
			if _, exists := r.Header["Cookie"]; exists {
				for i, entry := range r.Header["Cookie"] {
					var updatedEntry []string
					var updateCookie bool
					for _, cookie := range strings.Split(entry, ";") {
						s := strings.TrimSpace(cookie)
						if strings.HasPrefix(s, usr.TokenName+"=") {
							// Skip the cookie matching the token name.
							updateCookie = true
							continue
						}
						if strings.Contains(s, usr.Token) {
							// Skip the cookie with the value matching user token.
							updateCookie = true
							continue
						}
						updatedEntry = append(updatedEntry, cookie)
					}
					if updateCookie {
						r.Header["Cookie"][i] = strings.Join(updatedEntry, ";")
					}
				}
			}
		}
	}
}
