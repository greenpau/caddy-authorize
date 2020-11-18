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

package jwt

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	jwtauth "github.com/greenpau/caddy-auth-jwt/pkg/auth"
	"github.com/satori/go.uuid"
	"net/http"
)

func init() {
	caddy.RegisterModule(AuthMiddleware{})
}

// AuthMiddleware authorizes access to endpoints based on
// the presense and content of JWT token.
type AuthMiddleware struct {
	Authorizer *jwtauth.Authorizer `json:"authorizer,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (AuthMiddleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.jwt",
		New: func() caddy.Module { return new(AuthMiddleware) },
	}
}

// Provision provisions JWT authorization provider
func (m *AuthMiddleware) Provision(ctx caddy.Context) error {
	opts := make(map[string]interface{})
	opts["logger"] = ctx.Logger(m)
	return m.Authorizer.Provision(opts)
}

// Validate implements caddy.Validator.
func (m *AuthMiddleware) Validate() error {
	return nil
}

// Authenticate authorizes access based on the presense and content of JWT token.
func (m AuthMiddleware) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	reqID := GetRequestID(r)
	opts := make(map[string]interface{})
	opts["request_id"] = reqID
	user, authOK, err := m.Authorizer.Authenticate(w, r, opts)
	if user == nil {
		return caddyauth.User{}, authOK, err
	}
	userIdentity := caddyauth.User{
		Metadata: map[string]string{
			"roles": user["roles"].(string),
		},
	}
	if v, exists := user["id"]; exists {
		userIdentity.ID = v.(string)
	}
	for _, k := range []string{"claim_id", "sub", "email", "name"} {
		if v, exists := user[k]; exists {
			userIdentity.Metadata[k] = v.(string)
		}
	}
	return userIdentity, authOK, err
}

// Interface guards
var (
	_ caddy.Provisioner       = (*AuthMiddleware)(nil)
	_ caddy.Validator         = (*AuthMiddleware)(nil)
	_ caddyauth.Authenticator = (*AuthMiddleware)(nil)
)

// GetRequestID returns request ID.
func GetRequestID(r *http.Request) string {
	rawRequestID := caddyhttp.GetVar(r.Context(), "request_id")
	if rawRequestID == nil {
		requestID := r.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = uuid.NewV4().String()
		}
		caddyhttp.SetVar(r.Context(), "request_id", requestID)
		return requestID
	}
	return rawRequestID.(string)
}
